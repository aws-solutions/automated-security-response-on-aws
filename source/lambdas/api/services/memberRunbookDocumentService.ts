// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  CreateDocumentCommand,
  DescribeDocumentCommand,
  DocumentAlreadyExists,
  DuplicateDocumentContent,
  GetParameterCommand,
  ListDocumentsCommand,
  ParameterNotFound,
  SSMClient,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
} from '@aws-sdk/client-ssm';
import {
  MemberAccountCredentialsProvider,
  MemberCredentials,
  buildMemberSessionName,
} from './memberAccountCredentials';
import { SECURITY_CONTROL_STANDARD_NAME, SECURITY_CONTROL_STANDARD_VERSION } from '@asr/data-models';

export interface DeployDocumentParams {
  memberAccountId: string;
  documentName: string;
  content: string;
  controlId: string;
  actor?: string;
}

export interface MemberDocumentDeploymentResult {
  succeeded: Array<{ accountId: string; ssmDocumentVersion: string }>;
  failed: Array<{ accountId: string; error: string }>;
}

export interface PreparedMemberDocumentTarget {
  accountId: string;
  ssmClient: SSMClient;
}

export interface MemberDocumentPreflightResult {
  ready: PreparedMemberDocumentTarget[];
  collisions: Array<{ accountId: string; documentName: string }>;
  failed: Array<{ accountId: string; error: string }>;
}

const SOLUTION_PREFIX = 'SO0111';

/**
 * A built-in ASR runbook document name, captured down to its control id regardless of the
 * standard prefix: `ASR-SC_2.0.0_S3.9`, `ASR-CIS_3.0.0_S3.9`, and
 * `ASR-AFSBP_1.0.0_CloudTrail.7` all yield their trailing control id. `ASR-Custom-*`
 * documents are excluded so a customer's own custom runbook is never mistaken for a built-in
 * collision. The control-id suffix is alphanumeric because ASR ships non-numeric control ids
 * (`Inspector.InstanceVulnerability`).
 *
 * This deliberately mirrors the gap-detection tool's `ASR-.*_(control)` shape rather than a
 * stricter `{standard}_{version}` decomposition: a security guard must be at LEAST as broad
 * as the coverage detector, so any built-in the gap tool counts as covering a control is also
 * blocked from custom authoring here. A stricter pattern would be the dangerous direction — a
 * built-in the gap tool recognizes but this rejects would let a custom runbook install over
 * it. If the two must share one definition, extract an exported helper; keeping them aligned
 * in breadth is the invariant that matters.
 */
const ASR_BUILTIN_DOCUMENT_CONTROL_ID = /^ASR-(?!Custom-).*_([A-Za-z0-9]+\.[A-Za-z0-9]+)$/;

/** Page ceiling for the per-account ListDocuments scan, matching the gap-detection tool's 100. */
const MAX_DOCUMENT_PAGES = 100;

/**
 * Installs a custom runbook's SSM Automation document into member accounts,
 * one own copy per account (no cross-account document sharing).
 *
 * Each account therefore owns and can be audited on its own document, and the
 * Orchestrator in that account resolves a plain local document name — never an
 * owner-qualified `{adminAccountId}:{documentName}` reference.
 */
export class MemberRunbookDocumentService {
  constructor(
    private readonly logger: Logger,
    private readonly credentialsProvider: MemberAccountCredentialsProvider = new MemberAccountCredentialsProvider(),
    private readonly ssmClientFactory: (credentials: MemberCredentials) => SSMClient = (credentials) =>
      new SSMClient({ credentials, maxAttempts: 3 }),
  ) {}

  /**
   * Prepare member-account SSM clients and verify that the managed Custom Runbook would not
   * overlap a built-in remediation for the same control.
   *
   * Each member account is scanned for its ASR-* built-in Automation documents, and a
   * collision is reported when a built-in exists for this control under ANY loaded playbook
   * standard — matched at the control-id level, so `ASR-CIS_3.0.0_S3.9` blocks a custom
   * runbook for `S3.9` even when the SC playbook is not deployed. Both the finding's control
   * id and `remediationControlId` (the control whose built-in would actually run after a
   * remap such as S3.9 → CloudTrail.7, resolved by the caller in the admin account) are
   * checked, because a remapped built-in is named after the target control.
   *
   * Fail-closed: an account whose scan errors, or whose document list is truncated before a
   * collision is found, is excluded from the deployment target set rather than treated as
   * safe — installing a custom document over a control the solution owns is worse than a
   * skipped account the caller can retry.
   *
   * The returned clients use the same credentials later used for document installation,
   * keeping the release at one member-account credential hop for the preflight plus install.
   */
  async prepareDeploymentTargets(
    memberAccountIds: string[],
    controlId: string,
    remediationControlId: string,
    actor?: string,
  ): Promise<MemberDocumentPreflightResult> {
    const ready: PreparedMemberDocumentTarget[] = [];
    const collisions: Array<{ accountId: string; documentName: string }> = [];
    const failed: Array<{ accountId: string; error: string }> = [];
    const collidingControlIds = new Set([controlId, remediationControlId]);

    for (const accountId of memberAccountIds) {
      try {
        const credentials = await this.credentialsProvider.getCredentials(
          accountId,
          buildMemberSessionName('document-deploy', actor),
        );
        const ssmClient = this.ssmClientFactory(credentials);

        const collision = await this.findBuiltInCollision(ssmClient, collidingControlIds);
        if (collision) {
          collisions.push({ accountId, documentName: collision });
        } else {
          ready.push({ accountId, ssmClient });
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.logger.error('Failed to verify that a member account has no built-in runbook', {
          accountId,
          controlId,
          error: message,
        });
        failed.push({ accountId, error: message });
      }
    }

    return { ready, collisions, failed };
  }

  /**
   * Return the name of a built-in document that already remediates one of `collidingControlIds`
   * in this account, or undefined when none exists. Throws when the document list is truncated
   * before the page ceiling without finding a match, so the caller fails the account closed
   * rather than assuming no built-in exists beyond the pages it read.
   */
  private async findBuiltInCollision(
    ssmClient: SSMClient,
    collidingControlIds: ReadonlySet<string>,
  ): Promise<string | undefined> {
    let nextToken: string | undefined;
    let pages = 0;
    do {
      const response = await ssmClient.send(
        new ListDocumentsCommand({
          Filters: [
            { Key: 'DocumentType', Values: ['Automation'] },
            { Key: 'Owner', Values: ['Self'] },
            // Server-side prefix filter so the page budget is spent on ASR documents. The
            // ASR-Custom- exclusion happens client-side (a Name prefix filter cannot express it).
            { Key: 'Name', Values: ['ASR-'] },
          ],
          MaxResults: 50,
          NextToken: nextToken,
        }),
      );
      for (const documentIdentifier of response.DocumentIdentifiers ?? []) {
        const documentName = documentIdentifier.Name;
        if (!documentName) continue;
        const controlIdMatch = ASR_BUILTIN_DOCUMENT_CONTROL_ID.exec(documentName);
        if (controlIdMatch && collidingControlIds.has(controlIdMatch[1])) return documentName;
      }
      nextToken = response.NextToken;
      pages++;
    } while (nextToken && pages < MAX_DOCUMENT_PAGES);

    if (nextToken) {
      // The list was truncated at the page ceiling and no collision was found on the pages
      // read. A built-in for this control could still exist on an unread page, so fail closed.
      throw new Error('Built-in runbook verification incomplete: member account document list was truncated');
    }
    return undefined;
  }

  /**
   * Resolve the control whose built-in runbook actually remediates `controlId`.
   *
   * ASR points some controls at another control's remediation (S3.9 executes
   * CloudTrail.7), published as an SSM `remap` parameter. Those parameters are
   * created only by the playbook Primary (administrator) stack, so this MUST be
   * called with an ADMINISTRATOR-account SSM client — a member account holds no
   * remap parameters and would always fall back to the raw control id, defeating
   * the built-in collision guard. Returns `controlId` unchanged when no remap
   * exists (the common case).
   *
   * The remap parameter path uses the fixed Security Control standard and version:
   * Managed Custom Runbooks are always the consolidated SC standard, so these are
   * derived from constants rather than caller input.
   */
  async resolveRemediationControlId(ssmClient: SSMClient, controlId: string): Promise<string> {
    const remapParameterName = `/Solutions/${SOLUTION_PREFIX}/${SECURITY_CONTROL_STANDARD_NAME}/${SECURITY_CONTROL_STANDARD_VERSION}/${controlId}/remap`;

    try {
      const response = await ssmClient.send(new GetParameterCommand({ Name: remapParameterName }));
      return response.Parameter?.Value || controlId;
    } catch (error) {
      if (error instanceof ParameterNotFound) return controlId;
      throw error;
    }
  }

  /**
   * Create or update the document in one member account and make the resulting
   * version the default.
   *
   * The default version is what an unqualified `StartAutomationExecution` runs,
   * and UpdateDocument does not promote it — without the explicit promotion an
   * updated runbook would be installed but never executed.
   *
   * @returns the SSM document version now serving as default in that account
   */
  async deployDocumentToAccount(params: DeployDocumentParams): Promise<string> {
    const { memberAccountId, actor } = params;
    const credentials = await this.credentialsProvider.getCredentials(
      memberAccountId,
      buildMemberSessionName('document-deploy', actor),
    );
    const ssmClient = this.ssmClientFactory(credentials);
    return this.deployDocumentWithClient(params, ssmClient);
  }

  private async deployDocumentWithClient(params: DeployDocumentParams, ssmClient: SSMClient): Promise<string> {
    const { memberAccountId, documentName, content, controlId } = params;
    const documentVersion = await this.createOrUpdateDocument(ssmClient, documentName, content, controlId);

    await ssmClient.send(
      new UpdateDocumentDefaultVersionCommand({
        Name: documentName,
        DocumentVersion: documentVersion,
      }),
    );

    this.logger.info('Installed custom runbook document in member account', {
      memberAccountId,
      documentName,
      documentVersion,
      controlId,
    });
    return documentVersion;
  }

  private async createOrUpdateDocument(
    ssmClient: SSMClient,
    documentName: string,
    content: string,
    controlId: string,
  ): Promise<string> {
    try {
      const created = await ssmClient.send(
        new CreateDocumentCommand({
          Name: documentName,
          Content: content,
          DocumentType: 'Automation',
          DocumentFormat: 'YAML',
          Tags: [
            { Key: 'aws-solutions:solution-id', Value: SOLUTION_PREFIX },
            { Key: 'aws-solutions:custom-runbook', Value: controlId },
          ],
        }),
      );
      return created.DocumentDescription?.DocumentVersion ?? '1';
    } catch (error) {
      if (!(error instanceof DocumentAlreadyExists)) throw error;
    }

    try {
      const updated = await ssmClient.send(
        new UpdateDocumentCommand({
          Name: documentName,
          Content: content,
          DocumentVersion: '$LATEST',
          DocumentFormat: 'YAML',
        }),
      );
      return (
        updated.DocumentDescription?.DocumentVersion ?? (await this.describeLatestVersion(ssmClient, documentName))
      );
    } catch (error) {
      // The account already holds this exact content — nothing to update, but the
      // existing version still has to be promoted to default below.
      if (error instanceof DuplicateDocumentContent) {
        return this.describeLatestVersion(ssmClient, documentName);
      }
      throw error;
    }
  }

  private async describeLatestVersion(ssmClient: SSMClient, documentName: string): Promise<string> {
    const described = await ssmClient.send(
      new DescribeDocumentCommand({ Name: documentName, DocumentVersion: '$LATEST' }),
    );
    return described.Document?.DocumentVersion ?? '1';
  }

  /**
   * Install the document in each named account. A failure in one account never
   * blocks the others — partial rollouts are expected and are reported per
   * account so the caller can retry just the stragglers.
   */
  async deployToAccounts(
    memberAccountIds: string[],
    documentName: string,
    content: string,
    controlId: string,
    actor?: string,
  ): Promise<MemberDocumentDeploymentResult> {
    const succeeded: Array<{ accountId: string; ssmDocumentVersion: string }> = [];
    const failed: Array<{ accountId: string; error: string }> = [];

    for (const accountId of memberAccountIds) {
      try {
        const ssmDocumentVersion = await this.deployDocumentToAccount({
          memberAccountId: accountId,
          documentName,
          content,
          controlId,
          actor,
        });
        succeeded.push({ accountId, ssmDocumentVersion });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.logger.error('Failed to install custom runbook document in member account', {
          accountId,
          documentName,
          error: message,
        });
        failed.push({ accountId, error: message });
      }
    }

    return { succeeded, failed };
  }

  /**
   * Install a document using member-account clients prepared by
   * `prepareDeploymentTargets`, so the built-in preflight and the write share
   * one credential hop per account.
   */
  async deployToPreparedAccounts(
    targets: readonly PreparedMemberDocumentTarget[],
    documentName: string,
    content: string,
    controlId: string,
    actor?: string,
  ): Promise<MemberDocumentDeploymentResult> {
    const succeeded: Array<{ accountId: string; ssmDocumentVersion: string }> = [];
    const failed: Array<{ accountId: string; error: string }> = [];

    for (const target of targets) {
      try {
        const ssmDocumentVersion = await this.deployDocumentWithClient(
          {
            memberAccountId: target.accountId,
            documentName,
            content,
            controlId,
            actor,
          },
          target.ssmClient,
        );
        succeeded.push({ accountId: target.accountId, ssmDocumentVersion });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.logger.error('Failed to install custom runbook document in member account', {
          accountId: target.accountId,
          documentName,
          error: message,
        });
        failed.push({ accountId: target.accountId, error: message });
      }
    }

    return { succeeded, failed };
  }
}
