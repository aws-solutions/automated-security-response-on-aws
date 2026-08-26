// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  ASFFFinding,
  FindingId,
  FindingTableItem,
  remediationStatus,
  normalizeSeverity,
  ResolvedFindingType,
} from '@asr/data-models';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { gzip } from 'pako';
import { FindingRepository } from '../repositories/findingRepository';
import { Clock, getClock } from '../utils/clock';
import {
  sanitizeControlId,
  sanitizeFindingId,
  IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE,
} from '../utils/findingUtils';
import { getLogger } from '../utils/logger';
import { mapRemediationStatus } from '../utils/remediationStatusMapper';
import { calculateTtlTimestamp } from '../utils/ttlUtils';

/**
 * Metric-enrichment flags computed at ingestion (from finding-type notification
 * config matching) and persisted on the finding for the successful-remediation
 * metric. Omitted by callers that do not evaluate configs (e.g. API replay).
 */
export type FindingMetricEnrichment = Pick<
  FindingTableItem,
  'hasFindingNotificationsEnabled' | 'hasFindingRemediationDeadlineConfigured'
>;

/** Parameters for {@link FindingDataService.buildFindingTableItem}. */
interface BuildFindingTableItemParams {
  finding: ASFFFinding;
  sanitizedFindingId: FindingId;
  sanitizedControlId: string;
  suppressed: boolean;
  remediationStatus: remediationStatus;
  remediationStatusDetail?: string;
  eventBridgeTime?: string;
  metricEnrichment?: FindingMetricEnrichment;
}

/** Matches a 12-digit AWS account id. */
const AWS_ACCOUNT_ID_PATTERN = /^\d{12}$/;

export function normalizeResourceType(resourceType: string): string {
  return resourceType.replace(/\W/g, '').toLowerCase();
}

/** Manages interactions with the Findings DynamoDB table */
export class FindingDataService {
  private readonly dynamoDBDocumentClient: DynamoDBDocumentClient;
  private readonly findingRepository: FindingRepository;
  private readonly logger = getLogger('FindingDataService');

  /** @param tableName Findings table name
   * @param dynamoDBDocumentClient DynamoDB client instance
   * @param principal
   */
  constructor(
    private readonly tableName: string,
    dynamoDBDocumentClient: DynamoDBDocumentClient,
    private readonly principal: string,
    private readonly clock: Clock = getClock(),
  ) {
    this.dynamoDBDocumentClient = dynamoDBDocumentClient;
    this.findingRepository = new FindingRepository(this.principal, this.tableName, this.dynamoDBDocumentClient);
  }

  /** Validates and returns required string value, throws if missing or empty */
  private getRequiredString(value: string | undefined, fieldName: string): string {
    if (!value || value.trim() === '') {
      throw new Error(`Required field ${fieldName} is missing or empty from finding`);
    }
    return value;
  }

  /**
   * Resolves the account that owns the resource a finding reports on.
   *
   * For IAM Access Analyzer external access findings from an organization
   * analyzer, ASFF `AwsAccountId` is the administrator (delegated-admin)
   * account, while the resource actually lives in the account named by
   * `ProductFields.ResourceOwnerAccount`. Prefer that field for Access
   * Analyzer findings so the stored account reflects the resource owner.
   * All other finding types — and Access Analyzer findings without the field
   * (e.g. per-account analyzers where the two already agree) — fall back to
   * `AwsAccountId`.
   */
  private resolveAccountId(finding: ASFFFinding, sanitizedControlId: string): string {
    if (sanitizedControlId === IAM_ACCESS_ANALYZER_EXTERNAL_ACCESS_FINDING_TYPE) {
      const resourceOwnerAccount = finding.ProductFields?.ResourceOwnerAccount;
      if (resourceOwnerAccount) {
        // ResourceOwnerAccount becomes the `accountId` used for account-scoped
        // authorization. It is a free-form ProductFields entry, so a value that
        // is not a 12-digit account id is rejected outright (the finding is not
        // stored) rather than silently attributed to the wrong account — fail
        // closed on this write path, matching the runbook parse script. The
        // history-write path falls back instead, since the remediation has
        // already run and must still be recorded.
        if (!AWS_ACCOUNT_ID_PATTERN.test(resourceOwnerAccount)) {
          throw new Error(`Invalid ResourceOwnerAccount: ${resourceOwnerAccount}`);
        }
        return resourceOwnerAccount;
      }
    }
    return this.getRequiredString(finding.AwsAccountId, 'AwsAccountId');
  }

  /**
   * Sanitizes the caller's findingType and finding id into the DynamoDB key pair.
   *
   * Does not resolve the key. Which source a findingType comes from depends on the finding's family,
   * and that distinction is erased by the time a finding reaches this service as ASFF, so callers
   * resolve it upstream where the family is still known (`resolveFindingType` for the pre-processor,
   * `resolveControlId` for the Security-Hub-only sync path) and pass a definite value. The branded
   * {@link ResolvedFindingType} is what makes that unskippable: only those two resolvers produce the
   * brand, so a plain string will not compile here. See ADR 0010.
   */
  private getSanitizedFindingAndControl(
    finding: ASFFFinding,
    findingType: ResolvedFindingType,
  ): {
    sanitizedFindingId: FindingId;
    sanitizedControlId: string;
  } {
    const sanitizedControlId = sanitizeControlId(findingType);
    const sanitizedFindingId = sanitizeFindingId(finding.Id, findingType, sanitizedControlId);

    return { sanitizedFindingId, sanitizedControlId };
  }

  /** Compresses JSON data to binary for storage */
  private compressJson(data: ASFFFinding): Uint8Array {
    return gzip(JSON.stringify(data));
  }

  private getSecurityHubTimestamp(finding: ASFFFinding, eventBridgeTime?: string): string {
    if (eventBridgeTime) {
      return eventBridgeTime;
    }
    if (finding.UpdatedAt) {
      return finding.UpdatedAt;
    }
    if (finding.CreatedAt) {
      return finding.CreatedAt;
    }
    return this.clock.now().toISOString();
  }

  /** Builds common DynamoDB attributes for both put and update operations */
  private buildFindingTableItem(params: BuildFindingTableItemParams): FindingTableItem {
    const {
      finding,
      sanitizedFindingId,
      sanitizedControlId,
      suppressed,
      remediationStatus,
      remediationStatusDetail,
      eventBridgeTime,
      metricEnrichment,
    } = params;
    const now = this.clock.now().toISOString();
    const securityHubUpdate = this.getSecurityHubTimestamp(finding, eventBridgeTime);

    const resourceType = this.getRequiredString(finding.Resources?.[0]?.Type, 'Resources[0].Type'); // security control findings only ever have a single Resource
    const resourceTypeNormalized = normalizeResourceType(resourceType);
    const severityLabel = this.getRequiredString(finding.Severity?.Label, 'Severity.Label');

    const severityNormalized = normalizeSeverity(severityLabel);

    return {
      findingDescription: this.getRequiredString(finding.Title, 'Title'),
      accountId: this.resolveAccountId(finding, sanitizedControlId),
      resourceId: this.getRequiredString(finding.Resources[0].Id, 'Resources[0].Id'),
      resourceType: resourceType,
      resourceTypeNormalized: resourceTypeNormalized,
      severity: severityLabel,
      severityNormalized: severityNormalized,
      region: this.getRequiredString(finding.Region, 'region'),
      remediationStatus: remediationStatus,
      securityHubUpdatedAtTime: securityHubUpdate,
      lastUpdatedTime: now,
      'securityHubUpdatedAtTime#findingId': `${securityHubUpdate}#${sanitizedFindingId}`,
      'severityNormalized#securityHubUpdatedAtTime#findingId': `${severityNormalized}#${securityHubUpdate}#${sanitizedFindingId}`,
      findingJSON: this.compressJson(finding),
      FINDING_CONSTANT: 'finding',
      findingType: sanitizedControlId,
      findingId: sanitizedFindingId,
      findingIdControl: `${sanitizedFindingId}#${sanitizedControlId}`,
      creationTime: finding.CreatedAt,
      suppressed: suppressed,
      expireAt: calculateTtlTimestamp(now),
      ...(remediationStatusDetail !== undefined && { remediationStatusDetail }),
      ...(finding.FirstObservedAt !== undefined && { firstDetectedTime: finding.FirstObservedAt }),
      ...(metricEnrichment?.hasFindingNotificationsEnabled !== undefined && {
        hasFindingNotificationsEnabled: metricEnrichment.hasFindingNotificationsEnabled,
      }),
      ...(metricEnrichment?.hasFindingRemediationDeadlineConfigured !== undefined && {
        hasFindingRemediationDeadlineConfigured: metricEnrichment.hasFindingRemediationDeadlineConfigured,
      }),
    };
  }

  /** Returns true if the finding has been sent to ASR for execution (remediationStatus is not NOT_STARTED)
   * @param findingType The resolved partition key. See {@link FindingDataService.getSanitizedFindingAndControl}. */
  async hasBeenTriggered(finding: ASFFFinding, findingType: ResolvedFindingType): Promise<boolean> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding, findingType);
    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);

    if (!item || !item.remediationStatus) return false;

    const remediationStatus = item.remediationStatus;
    return remediationStatus !== 'NOT_STARTED';
  }

  /** @param findingType The resolved partition key. See {@link FindingDataService.getSanitizedFindingAndControl}. */
  async hasPreviouslyFailedRemediation(finding: ASFFFinding, findingType: ResolvedFindingType): Promise<boolean> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding, findingType);
    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);

    if (!item || !item.remediationStatus) return false;

    const remediationStatus = item.remediationStatus;
    return remediationStatus === 'FAILED';
  }

  /**
   * Returns how many times auto-remediation has been triggered for this finding
   * and when the last attempt was, read from the cached finding item. The
   * retry-cap gate uses this to bound and space out retries on a
   * repeatedly-failing finding. Returns zero attempts (and no timestamp) when the
   * finding has no record yet.
   *
   * @param findingType The resolved partition key. See {@link FindingDataService.getSanitizedFindingAndControl}.
   */
  async getRemediationAttemptInfo(
    finding: ASFFFinding,
    findingType: ResolvedFindingType,
  ): Promise<{ attempts: number; lastAttemptTime?: string }> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding, findingType);
    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);
    return {
      attempts: item?.remediationAttempts ?? 0,
      lastAttemptTime: item?.lastRemediationAttemptTime,
    };
  }

  /** @param findingType The resolved partition key. See {@link FindingDataService.getSanitizedFindingAndControl}. */
  async isNew(finding: ASFFFinding, findingType: ResolvedFindingType): Promise<boolean> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding, findingType);

    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);
    return !item;
  }

  /**
   * @param findingType The resolved partition key, second so it cannot be omitted. See
   * {@link FindingDataService.getSanitizedFindingAndControl}.
   */
  async updateWithIncomingData(
    finding: ASFFFinding,
    findingType: ResolvedFindingType,
    newRemediationStatus?: remediationStatus,
    isFull: boolean = false,
    eventBridgeTime?: string,
    metricEnrichment?: FindingMetricEnrichment,
  ): Promise<{ status: 'SUCCESS' | 'FAILED' | 'ERROR'; findingTableItem?: FindingTableItem }> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding, findingType);

    const isArchived = finding.RecordState === 'ARCHIVED' || finding.Compliance?.Status === 'PASSED';

    if (isArchived && isFull) {
      return { status: 'SUCCESS' };
    }

    if (isArchived) {
      const status = await this.findingRepository.deleteIfExists(sanitizedFindingId, sanitizedControlId);
      return { status };
    }

    const oldFindingTableItem = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);

    const remediationStatus = mapRemediationStatus(
      newRemediationStatus || oldFindingTableItem?.remediationStatus || 'NOT_STARTED',
    );
    const remediationStatusDetail = oldFindingTableItem?.remediationStatusDetail;
    const suppressed = oldFindingTableItem?.suppressed || false;
    this.logger.debug('Syncing finding table data...', {
      remediationStatus: remediationStatus,
      suppressed: suppressed,
      findingId: finding.Id,
      isFull,
    });

    let findingTableItem: FindingTableItem;
    try {
      findingTableItem = this.buildFindingTableItem({
        finding,
        sanitizedFindingId,
        sanitizedControlId,
        suppressed,
        remediationStatus,
        remediationStatusDetail,
        eventBridgeTime,
        metricEnrichment,
      });
    } catch (error) {
      this.logger.error(
        `Encountered error constructing Finding Table Item for finding ${finding.Id}. This finding cannot be processed and requires manual investigation.`,
      );
      return { status: 'ERROR' };
    }

    let status: 'SUCCESS' | 'FAILED' | 'ERROR';
    if (await this.findingRepository.exists(sanitizedFindingId, sanitizedControlId)) {
      status = await this.findingRepository.putIfNewer(findingTableItem);
    } else {
      status = await this.findingRepository.createIfNotExists(findingTableItem);
    }

    return { status, findingTableItem };
  }
}
