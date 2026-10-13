// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  SSMClient,
  ListDocumentsCommand,
  GetDocumentCommand,
  InvalidDocument,
  DocumentIdentifier,
} from '@aws-sdk/client-ssm';
import {
  ListRunbooksParams,
  RunbookId,
  RunbookIdSchema,
  RunbookMetadata,
  RunbookMetadataSummary,
  RunbookType,
} from '@asr/data-models';
import { CustomRunbookRepository } from '../../common/repositories/customRunbookRepository';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { assertCustomRunbooksConfigured, optionalCustomRunbookEnvironment } from '../apiLambdaEnvironment';
import { NotFoundError } from '../../common/utils/httpErrors';

/** Result of a get_runbook lookup — custom runbooks carry an optional python script. */
export interface GetRunbookResult {
  metadata: RunbookMetadataSummary;
  yaml_content: string;
  python_script?: string;
}

/**
 * Extracts the control ID (e.g. "IAM.1") from a built-in SSM document name
 * like "ASR-SC_1.0_IAM.1". Returns undefined if the name doesn't match.
 */
function extractControlIdFromDocumentName(documentName: string): string | undefined {
  // Pattern: ASR-<standard>_<version>_<controlId>
  const match = /^ASR-[^_]+_[^_]+_(.+)$/.exec(documentName);
  return match?.[1];
}

/**
 * Projects one solution-owned SSM document into an API summary, or returns
 * undefined when the document should be skipped: it isn't a built-in ASR runbook
 * (custom runbooks carry the `ASR-Custom-` prefix and are served from DynamoDB),
 * it isn't a *control* runbook, or its extracted control doesn't match the
 * requested `controlId`.
 *
 * The solution also deploys shared remediation documents (`ASR-EnableVPCFlowLogs`,
 * `ASR-Orchestrator-*`) that control runbooks delegate to. Their names carry no
 * `<standard>_<version>_<control>` segment, so they have no control to report, and
 * `control_id` must not be overloaded with a document name. They are not control
 * runbooks, so they are omitted here. `get_runbook` still fetches any of them by name.
 *
 * Kept as a standalone function so the paginated listing loop stays a simple
 * fetch-and-collect and this per-document filtering/mapping is testable alone.
 */
function toBuiltinRunbookSummary(doc: DocumentIdentifier, controlId?: string): RunbookMetadataSummary | undefined {
  const documentName: string = doc.Name ?? '';
  if (!documentName.startsWith('ASR-') || documentName.startsWith('ASR-Custom-')) return undefined;

  const extractedControlId = extractControlIdFromDocumentName(documentName);
  if (!extractedControlId) return undefined;

  // Client-side filter: skip documents whose extracted control doesn't match
  if (controlId && extractedControlId !== controlId) return undefined;

  return {
    runbook_id: documentName,
    control_id: extractedControlId,
    type: 'builtin',
    status: 'DEPLOYED',
    version: doc.DocumentVersion ? Number.parseInt(doc.DocumentVersion, 10) : 1,
    description: doc.DisplayName ?? documentName,
    service_name: extractedControlId.split('.')[0],
    created_at: doc.CreatedDate?.toISOString() ?? '',
    ssm_document_name: documentName,
  };
}

/**
 * Read side of the custom-runbook API: lists and fetches both custom runbooks
 * (DynamoDB + S3) and built-in ASR SSM documents. Owns its own SSM/S3 clients and
 * the custom-runbook repository so the handler stays a thin HTTP layer.
 */
export class CustomRunbookQueryService {
  private ssmClient: SSMClient | undefined;
  private s3Client: S3Client | undefined;
  private runbookRepository: CustomRunbookRepository | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly ssmClientFactory: () => SSMClient = () => new SSMClient({ maxAttempts: 3 }),
    private readonly s3ClientFactory: () => S3Client = () => new S3Client({ maxAttempts: 3 }),
  ) {}

  private getSsmClient(): SSMClient {
    this.ssmClient ??= this.ssmClientFactory();
    return this.ssmClient;
  }

  private getS3Client(): S3Client {
    this.s3Client ??= this.s3ClientFactory();
    return this.s3Client;
  }

  private getRunbookRepository(): CustomRunbookRepository {
    if (!this.runbookRepository) {
      const { tableName } = assertCustomRunbooksConfigured();
      this.runbookRepository = new CustomRunbookRepository(tableName, createDynamoDBClient({ maxAttempts: 10 }));
    }
    return this.runbookRepository;
  }

  /**
   * Lists custom runbooks, built-in runbooks, or both, honoring the MCP-blueprint
   * gate: an explicit custom-only request on an unconfigured deployment throws 501,
   * while an unfiltered request degrades to built-ins only when custom storage is absent.
   */
  async listRunbooks(params: ListRunbooksParams): Promise<{ runbooks: RunbookMetadataSummary[] }> {
    const requestedType: RunbookType | undefined = params.type;
    const includeCustom = !requestedType || requestedType === 'custom';
    const includeBuiltin = !requestedType || requestedType === 'builtin';
    const customConfig = optionalCustomRunbookEnvironment();

    // Explicit custom-only request on an unconfigured deployment → 501.
    if (requestedType === 'custom' && !customConfig) {
      assertCustomRunbooksConfigured();
    }

    const customSummaries: RunbookMetadataSummary[] =
      includeCustom && customConfig ? await this.loadCustomRunbookSummaries(params.control_id, params.status) : [];

    const builtinSummaries: RunbookMetadataSummary[] =
      includeBuiltin && params.status !== 'DRAFT' ? await this.listBuiltinRunbooks(params.control_id) : [];

    return { runbooks: [...customSummaries, ...builtinSummaries] };
  }

  /** Fetches a single runbook by id — a built-in SSM document or a custom runbook from S3. */
  async getRunbook(runbookIdRaw: string): Promise<GetRunbookResult> {
    // Built-in documents do not depend on MCP-owned custom-runbook storage.
    if (runbookIdRaw.startsWith('ASR-') && !runbookIdRaw.startsWith('ASR-Custom-')) {
      const { summary, yamlContent } = await this.getBuiltinRunbook(runbookIdRaw);
      return { metadata: summary, yaml_content: yamlContent };
    }

    // A non-builtin id that isn't a valid RunbookId (e.g. "foo" or a truncated
    // uuid) passes GetRunbookSchema's .min(1) but is not a real runbook — treat it
    // as a miss rather than letting RunbookIdSchema.parse throw a raw ZodError (500).
    const parsedRunbookId = RunbookIdSchema.safeParse(runbookIdRaw);
    if (!parsedRunbookId.success) {
      throw new NotFoundError(`Runbook not found: ${runbookIdRaw}`);
    }
    const metadata = await this.getRunbookRepository().findLatestVersion(parsedRunbookId.data);
    if (metadata) {
      return this.getCustomRunbookResponse(metadata);
    }

    throw new NotFoundError(`Runbook not found: ${runbookIdRaw}`);
  }

  private async loadCustomRunbookSummaries(
    controlId?: string,
    status?: ListRunbooksParams['status'],
  ): Promise<RunbookMetadataSummary[]> {
    const repo = this.getRunbookRepository();
    const runbooks = controlId ? await repo.findByControlId(controlId) : await repo.findAll();
    const filtered = status ? runbooks.filter((r) => r.status === status) : runbooks;
    // Both findAll (scan) and findByControlId (GSI query) return every version of
    // a runbook, keyed by (runbookId, version). Collapse to the latest version per
    // runbookId so list_runbooks emits one row per runbook rather than one per version.
    // When a status filter is applied it runs BEFORE the collapse (by design), so the
    // selected row is the latest version *that matches the filter* — which may not be
    // the runbook's absolute newest version if a newer version has a different status.
    const latestByRunbookId = new Map<RunbookId, RunbookMetadata>();
    for (const runbook of filtered) {
      const current = latestByRunbookId.get(runbook.runbookId);
      if (!current || runbook.version > current.version) {
        latestByRunbookId.set(runbook.runbookId, runbook);
      }
    }
    return [...latestByRunbookId.values()].map((r) => ({
      runbook_id: r.runbookId,
      control_id: r.controlId,
      type: 'custom' as const,
      status: r.status,
      version: r.version,
      description: r.description,
      service_name: r.serviceName,
      created_at: r.createdAt,
      deployed_at: r.deployedAt,
      ssm_document_name: r.ssmDocumentName,
    }));
  }

  /**
   * Lists built-in SSM automation documents deployed by the solution.
   * Built-in documents follow the naming convention `ASR-<standard>_<version>_<controlId>`.
   */
  private async listBuiltinRunbooks(controlId?: string): Promise<RunbookMetadataSummary[]> {
    const client = this.getSsmClient();

    // Use only Owner and DocumentType server-side. The control_id filter is applied
    // client-side after extraction because the naming convention spans multiple
    // standards/versions (ASR-SC_1.0_, ASR-SC_2.0.0_, etc.) and a hardcoded prefix
    // would miss documents deployed under a different standard or version.
    const filters = [
      { Key: 'Owner', Values: ['Self'] },
      { Key: 'DocumentType', Values: ['Automation'] },
    ];

    const summaries: RunbookMetadataSummary[] = [];
    let nextToken: string | undefined;
    let pageCount = 0;
    // Bound the scan the same way resolveDocumentName does, so a pathological
    // document inventory can't spin this listing unbounded. A truncated listing
    // is acceptable here (unlike resolveDocumentName, a miss isn't dangerous),
    // so this logs and stops rather than throwing.
    const MAX_PAGES = 20;

    do {
      const response = await client.send(
        new ListDocumentsCommand({
          Filters: filters,
          NextToken: nextToken,
          MaxResults: 50,
        }),
      );

      for (const doc of response.DocumentIdentifiers ?? []) {
        const summary = toBuiltinRunbookSummary(doc, controlId);
        if (summary) summaries.push(summary);
      }

      nextToken = response.NextToken;
      pageCount++;
      if (pageCount >= MAX_PAGES && nextToken) {
        this.logger.warn('Truncating built-in runbook listing after reaching the page cap', { MAX_PAGES });
        break;
      }
    } while (nextToken);

    return summaries;
  }

  /**
   * Fetches a built-in SSM automation document by name and returns its content.
   *
   * Unlike the listing, this serves shared documents too (`ASR-EnableVPCFlowLogs`,
   * `ASR-Orchestrator-*`): a caller who names one gets it. Their names carry no
   * `<standard>_<version>_<control>` segment, so `control_id` and `service_name` are empty for
   * them rather than filled with the document name — `control_id` means a control, and a
   * client keying on it must not be handed a document name that merely looks like one.
   */
  private async getBuiltinRunbook(documentName: string): Promise<{
    summary: RunbookMetadataSummary;
    yamlContent: string;
  }> {
    const client = this.getSsmClient();

    let response;
    try {
      response = await client.send(
        new GetDocumentCommand({
          Name: documentName,
          DocumentFormat: 'YAML',
        }),
      );
    } catch (error) {
      // SSM throws InvalidDocument for a nonexistent document — map to 404.
      if (error instanceof InvalidDocument) {
        throw new NotFoundError(`Built-in runbook not found: ${documentName}`);
      }
      throw error;
    }

    if (!response.Content) {
      throw new NotFoundError(`Built-in runbook not found: ${documentName}`);
    }

    const extractedControlId = extractControlIdFromDocumentName(documentName);

    const summary: RunbookMetadataSummary = {
      runbook_id: documentName,
      control_id: extractedControlId ?? '',
      type: 'builtin',
      status: 'DEPLOYED',
      version: response.DocumentVersion ? Number.parseInt(response.DocumentVersion, 10) : 1,
      description: documentName,
      service_name: extractedControlId?.split('.')[0] ?? '',
      created_at: response.CreatedDate?.toISOString() ?? '',
      ssm_document_name: documentName,
    };

    return { summary, yamlContent: response.Content };
  }

  private async getCustomRunbookResponse(metadata: RunbookMetadata): Promise<GetRunbookResult> {
    const { bucketName } = assertCustomRunbooksConfigured();
    const s3Response = await this.getS3Client().send(
      new GetObjectCommand({
        Bucket: bucketName,
        Key: metadata.s3Key,
      }),
    );
    const yamlContent = (await s3Response.Body?.transformToString()) ?? '';

    let pythonScript: string | undefined;
    if (metadata.scriptS3Key) {
      const scriptResponse = await this.getS3Client().send(
        new GetObjectCommand({
          Bucket: bucketName,
          Key: metadata.scriptS3Key,
        }),
      );
      pythonScript = (await scriptResponse.Body?.transformToString()) ?? undefined;
    }

    const summary: RunbookMetadataSummary = {
      runbook_id: metadata.runbookId,
      control_id: metadata.controlId,
      type: 'custom',
      status: metadata.status,
      version: metadata.version,
      description: metadata.description,
      service_name: metadata.serviceName,
      created_at: metadata.createdAt,
      deployed_at: metadata.deployedAt,
      ssm_document_name: metadata.ssmDocumentName,
    };

    return { metadata: summary, yaml_content: yamlContent, python_script: pythonScript };
  }
}
