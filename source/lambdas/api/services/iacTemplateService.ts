// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { inflate } from 'pako';
import { RemediationHistoryRepository } from '../../common/repositories/remediationHistoryRepository';

type HistoryRepository = Pick<RemediationHistoryRepository, 'findLatestSuccessWithFindingJSON'>;
import { IaCGuidanceService, IaCFormat, TemplateResolver } from '../../common/services/iacGuidanceService';
import { S3TemplateResolver } from '../../common/services/s3TemplateResolver';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { NotFoundError } from '../../common/utils/httpErrors';
import { getLogger } from '../../common/utils/logger';
import { getControlIdFromFindingId, sanitizeControlId } from '../../common/utils/findingUtils';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';
import { buildPlaceholderMap, PlaceholderMap, SecurityFindingData } from './controlPlaceholderMappings';
import type { FindingId, RemediationHistoryTableItem } from '@asr/data-models';

/**
 * Extracts the short control ID (e.g. `S3.2`) from a finding ARN.
 * `getControlIdFromFindingId` returns the full path (`security-control/S3.2`
 * for consolidated); this strips the `security-control/` prefix so the result
 * matches template directory names and placeholder mapping keys.
 *
 * Unconsolidated findings (Security Hub consolidation turned off) yield paths
 * like `aws-foundational-security-best-practices/v/1.0.0/S3.1`. These are
 * intentionally left intact: ASR keys templates and CONTROL_PLACEHOLDER_MAPPINGS
 * by the consolidated short ID, so an unconsolidated path simply won't match a
 * template and falls through to the "IaC unavailable" note. Supporting
 * unconsolidated findings would require standard-specific path parsing, which is
 * out of scope here.
 */
function extractShortControlId(findingId: string): string | undefined {
  const raw = getControlIdFromFindingId(findingId);
  if (!raw) return undefined;
  return raw.replace(/^security-control\//, '');
}

// Re-export for handler use
export { IaCFormatSchema } from '../../common/services/iacGuidanceService';
export type { PlaceholderMap } from './controlPlaceholderMappings';

/**
 * ASFF finding shape read from remediation history. Extends the
 * placeholder-extraction data (SecurityFindingData) with the `Compliance` block we
 * use for the controlId fallback when the ARN doesn't carry it.
 */
type HistorySecurityFinding = SecurityFindingData & {
  Compliance?: { SecurityControlId?: string };
};

/**
 * Structural type guard for the subset of ASFF we read from history. Narrows an
 * unknown (freshly JSON-parsed) value to HistorySecurityFinding without an
 * `as unknown as` double cast: the value must be a non-array object, and
 * `Resources` — the only field we index into positionally — must be an array
 * when present. Everything we touch beyond that is optional, so a minimal guard
 * is sufficient and keeps validation co-located with the narrowing.
 */
function isHistorySecurityFinding(value: unknown): value is HistorySecurityFinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const { Resources } = value as { Resources?: unknown };
  return Resources === undefined || Array.isArray(Resources);
}

/** Result of rendering an IaC template with placeholder replacements */
export interface IaCRenderResult {
  content: string;
  filename: string;
  controlId: string;
}

/** File extensions per format — the format's "own type" extension. */
const FORMAT_EXTENSION: Record<IaCFormat, string> = {
  'cloudformation-yaml': '.yaml',
  'cloudformation-json': '.json',
  terraform: '.tf',
  cdk: '.ts',
};

/**
 * Build the download filename for a rendered template.
 *
 * Every export is delivered as a `.txt` file (browsers/editors treat as plain
 * text) with the format's own type extension before the `.txt` so the
 * customer can still tell the IaC flavor at a glance:
 *   `S3.9.yaml.txt` · `S3.9.json.txt` · `S3.9.tf.txt` · `S3.9.ts.txt`
 *
 * The extension alone disambiguates the framework (`.tf` → Terraform,
 * `.ts` → CDK, `.yaml`/`.json` → CloudFormation), so we don't repeat the
 * format slug — `S3.9-cloudformation-yaml.yaml.txt` was redundant.
 */
function buildFilename(controlId: string, format: IaCFormat): string {
  // Slashes in the unconsolidated controlId path (e.g.
  // `cis-aws-foundations-benchmark/v/1.4.0/2.1.5.2`) would be stripped by
  // browsers from the `<a download>` attribute. Replace with underscore so
  // the customer downloads a recognizable file name.
  const safeControlId = controlId.replaceAll('/', '_');
  return `${safeControlId}${FORMAT_EXTENSION[format]}.txt`;
}

/**
 * Build a plain-text note filename for cases where no IaC template is rendered.
 * Kept as a simple `.txt` so customers receive a readable explanation rather
 * than an empty/typed file or an error.
 */
function buildNoteFilename(controlId: string): string {
  return `${controlId.replaceAll('/', '_')}-iac-unavailable.txt`;
}

/**
 * Service that orchestrates IaC template rendering for findings.
 *
 * Reuses the existing IaCGuidanceService/TemplateResolver pattern from the
 * notification channels, backed by an S3 resolver for the API Lambda.
 */
export class IaCTemplateService {
  private readonly historyRepository: HistoryRepository;
  private readonly guidanceService: IaCGuidanceService;
  private readonly logger = getLogger('IaCTemplateService');

  constructor(resolver: TemplateResolver, historyRepository: HistoryRepository) {
    this.historyRepository = historyRepository;
    this.guidanceService = new IaCGuidanceService(resolver);
  }

  /**
   * Fetches the remediation-history entry backing an IaC download — the latest
   * SUCCESS record carrying the compressed finding JSON. Exposed so the handler
   * can read the entry's authoritative `accountId` for account-scoped
   * authorization and then pass the same entry to
   * {@link renderTemplateForFinding}, avoiding a second DynamoDB read.
   */
  async fetchFindingForDownload(findingId: FindingId): Promise<RemediationHistoryTableItem | null> {
    return (await this.historyRepository.findLatestSuccessWithFindingJSON(findingId)) ?? null;
  }

  /**
   * Convenience wrapper that fetches the finding's remediation-history entry
   * and renders from it in one call. Equivalent to
   * {@link fetchFindingForDownload} followed by {@link renderTemplateForFinding};
   * used by callers that don't need the entry for anything else (e.g. an
   * authorization check).
   */
  async renderTemplate(findingId: FindingId, format: IaCFormat): Promise<IaCRenderResult> {
    const historyEntry = await this.fetchFindingForDownload(findingId);
    return this.renderTemplateForFinding(historyEntry, findingId, format);
  }

  /**
   * Renders an IaC template from an already-fetched remediation-history entry.
   * The handler fetches the entry once (for authorization) and passes it here
   * so the finding is read from DynamoDB only once. A missing entry yields the
   * "no finding data" note (templates require a successful remediation).
   */
  async renderTemplateForFinding(
    historyEntry: RemediationHistoryTableItem | null,
    findingId: FindingId,
    format: IaCFormat,
  ): Promise<IaCRenderResult> {
    const historyFinding = this.decodeFindingJSON(historyEntry, findingId);
    const rawControlId = extractShortControlId(findingId) ?? historyFinding?.Compliance?.SecurityControlId;
    const controlId = rawControlId ? sanitizeControlId(rawControlId) : undefined;

    if (!controlId) {
      throw new NotFoundError('Could not identify control from finding ARN');
    }

    const templates = await this.guidanceService.getTemplates(controlId, [format]);
    if (templates.length === 0) return this.buildNoTemplateNote(controlId, format);
    if (!historyFinding) return this.buildNoFindingDataNote(controlId, format);

    const placeholderMap = buildPlaceholderMap(controlId, historyFinding);
    const rendered = this.replacePlaceholders(templates[0].content, placeholderMap);
    return { content: rendered, filename: buildFilename(controlId, format), controlId };
  }

  /**
   * Renders an IaC template snippet without DynamoDB access.
   * Used where finding data is already available.
   */
  async renderSnippet(
    controlId: string,
    format: IaCFormat,
    placeholderMap: PlaceholderMap,
  ): Promise<string | undefined> {
    const templates = await this.guidanceService.getTemplates(controlId, [format]);
    if (templates.length === 0) {
      return undefined;
    }
    return this.replacePlaceholders(templates[0].content, placeholderMap);
  }

  /**
   * Builds a plain-text note explaining that no IaC template exists for the
   * given control. Returned (instead of a 404) when the control is known but
   * ASR ships no template for it — e.g. operational-only remediations such as
   * rotating credentials or terminating instances, which can't be expressed as
   * a reusable IaC snippet.
   */
  private buildNoTemplateNote(controlId: string, format: IaCFormat): IaCRenderResult {
    const content = [
      `# Infrastructure-as-Code is not available for control ${controlId}.`,
      '#',
      `# ASR does not ship a ${format} template for this control. This is usually because`,
      '# the remediation is operational rather than configuration-based — for example,',
      '# rotating or revoking credentials, terminating an instance, or deleting an unused',
      '# resource. Such actions do not map to a reusable IaC change you can apply to your',
      '# infrastructure definitions.',
      '#',
      '# Review the finding details in the ASR console and the AWS Security Hub remediation',
      '# guidance for this control to confirm the resource is in the desired state.',
      '',
    ].join('\n');
    return { content, filename: buildNoteFilename(controlId), controlId };
  }

  private buildNoFindingDataNote(controlId: string, format: IaCFormat): IaCRenderResult {
    const content = [
      `# A ${format} template is available for control ${controlId}, but it cannot be`,
      '# populated yet. IaC templates require finding data from a successful remediation.',
      '#',
      '# Once ASR successfully remediates this finding, retry the download to get a',
      '# fully resolved template with your resource values.',
      '',
    ].join('\n');
    return { content, filename: buildNoteFilename(controlId), controlId };
  }

  /**
   * Decompresses the stored finding JSON from a remediation-history entry.
   * Returns null when the entry is absent or carries no findingJSON, and
   * for corrupt data (logged); DynamoDB errors surface at fetch time instead.
   */
  private decodeFindingJSON(
    entry: RemediationHistoryTableItem | null,
    findingId: FindingId,
  ): HistorySecurityFinding | null {
    if (!entry?.findingJSON) return null;
    try {
      const parsed: unknown = JSON.parse(inflate(entry.findingJSON, { to: 'string' }));
      return isHistorySecurityFinding(parsed) ? parsed : null;
    } catch (error) {
      this.logger.warn('Failed to decompress findingJSON', { findingId, error });
      return null;
    }
  }

  /**
   * Replaces `{key}` tokens in a single pass so a replacement value that itself
   * contains a `{otherKey}` pattern can't be re-substituted in a later
   * iteration. Placeholder values originate from customer ASFF data
   * (semi-trusted), so cascading substitution is avoided deliberately. Keys
   * come from the hardcoded CONTROL_PLACEHOLDER_MAPPINGS, but they are still
   * regex-escaped defensively before being compiled into the alternation.
   */
  private replacePlaceholders(content: string, placeholders: PlaceholderMap): string {
    const keys = Object.keys(placeholders);
    if (keys.length === 0) return content;
    const pattern = new RegExp(keys.map((key) => String.raw`\{${escapeRegExp(key)}\}`).join('|'), 'g');
    return content.replaceAll(pattern, (match) => placeholders[match.slice(1, -1)] ?? match);
  }
}

/** Escapes characters with special meaning in a RegExp so a key is matched literally. */
function escapeRegExp(value: string): string {
  return value.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/**
 * Lazily builds and memoizes a fully-wired IaCTemplateService once per Lambda
 * container, owning all repository/resolver composition in the service layer so
 * handlers stay thin (HTTP concerns only) per ADR 0003. The DynamoDB client,
 * RemediationHistoryRepository, and S3TemplateResolver are constructed on first
 * use from the validated API Lambda environment.
 */
let iacTemplateServiceSingleton: IaCTemplateService | undefined;

export function getIaCTemplateService(): IaCTemplateService {
  if (!iacTemplateServiceSingleton) {
    const env = apiLambdaEnvironment();
    const dynamoDBClient = createDynamoDBClient({ maxAttempts: 10 });
    const historyRepository = new RemediationHistoryRepository(
      SCOPE_NAME,
      env.REMEDIATION_HISTORY_TABLE_NAME,
      dynamoDBClient,
      env.FINDINGS_TABLE_NAME,
    );
    iacTemplateServiceSingleton = new IaCTemplateService(
      new S3TemplateResolver(env.IAC_TEMPLATES_BUCKET),
      historyRepository,
    );
  }
  return iacTemplateServiceSingleton;
}
