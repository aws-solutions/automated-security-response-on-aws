// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ASFFFinding, FindingTableItem, remediationStatus, SEVERITY_MAPPING } from '@asr/data-models';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { gzip } from 'pako';
import { FindingRepository } from '../repositories/findingRepository';
import { getClock } from '../utils/clock';
import { getControlIdFromFindingId, sanitizeControlId } from '../utils/findingUtils';
import { getLogger } from '../utils/logger';
import { mapRemediationStatus } from '../utils/remediationStatusMapper';
import { calculateTtlTimestamp } from '../utils/ttlUtils';

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

  /** Sanitizes finding ID to ensure it's safe for DynamoDB keys */
  private sanitizeFindingId(findingId: string, controlIdFromFindingId: string, sanitizedControlId: string): string {
    // to keep dynamodb indexes consistent, the controlId embedded in the findingId should match what will be stored as findingType
    const findingIdWithSanitizedControlId = findingId.replace(controlIdFromFindingId, sanitizedControlId);
    // eslint-disable-next-line no-control-regex
    const CONTROL_CHARS = /[#\x00-\x1F\x7F]/g; // NOSONAR - sanitizing control chars
    return findingIdWithSanitizedControlId.replace(CONTROL_CHARS, '');
  }

  /** Compresses JSON data to binary for storage */
  private compressJson(data: ASFFFinding): Uint8Array {
    return gzip(JSON.stringify(data));
  }

  private getSanitizedFindingAndControl(finding: ASFFFinding): {
    sanitizedFindingId: string;
    sanitizedControlId: string;
  } {
    const controlIdFromFindingId = getControlIdFromFindingId(finding.Id) ?? finding.Compliance.SecurityControlId;
    const sanitizedControlId = sanitizeControlId(controlIdFromFindingId);
    const sanitizedFindingId = this.sanitizeFindingId(finding.Id, controlIdFromFindingId, sanitizedControlId);

    return { sanitizedFindingId, sanitizedControlId };
  }

  private static getSecurityHubTimestamp(finding: ASFFFinding): string {
    if (finding.UpdatedAt) {
      return finding.UpdatedAt;
    }
    if (finding.CreatedAt) {
      return finding.CreatedAt;
    }
    return getClock().now().toISOString();
  }

  /** Builds common DynamoDB attributes for both put and update operations */
  private buildFindingTableItem(
    finding: ASFFFinding,
    sanitizedFindingId: string,
    sanitizedControlId: string,
    suppressed: boolean,
    remediationStatus: remediationStatus,
  ): FindingTableItem {
    const now = getClock().now().toISOString();
    const securityHubUpdate = FindingDataService.getSecurityHubTimestamp(finding);

    const resourceType = this.getRequiredString(finding.Resources?.[0]?.Type, 'Resources[0].Type'); // security control findings only ever have a single Resource
    const resourceTypeNormalized = normalizeResourceType(resourceType);
    const severityLabel = this.getRequiredString(finding.Severity?.Label, 'Severity.Label');

    const severityNormalized = SEVERITY_MAPPING[severityLabel.toUpperCase()] ?? 0;

    return {
      findingDescription: this.getRequiredString(finding.Title, 'Title'),
      accountId: this.getRequiredString(finding.AwsAccountId, 'AwsAccountId'),
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
    };
  }

  /** Returns true if the finding has been sent to ASR for execution (remediationStatus is not NOT_STARTED) */
  async hasBeenTriggered(finding: ASFFFinding): Promise<boolean> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding);
    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);

    if (!item || !item.remediationStatus) return false;

    const remediationStatus = item.remediationStatus;
    return remediationStatus !== 'NOT_STARTED';
  }

  async hasPreviouslyFailedRemediation(finding: ASFFFinding): Promise<boolean> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding);
    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);

    if (!item || !item.remediationStatus) return false;

    const remediationStatus = item.remediationStatus;
    return remediationStatus === 'FAILED';
  }

  async isNew(finding: ASFFFinding): Promise<boolean> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding);

    const item = await this.findingRepository.findByIdWithCache(sanitizedFindingId, sanitizedControlId);
    return !item;
  }

  async updateWithIncomingData(
    finding: ASFFFinding,
    newRemediationStatus?: remediationStatus,
    isFull: boolean = false,
  ): Promise<{ status: 'SUCCESS' | 'FAILED' | 'ERROR'; findingTableItem?: FindingTableItem }> {
    const { sanitizedFindingId, sanitizedControlId } = this.getSanitizedFindingAndControl(finding);

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
    const suppressed = oldFindingTableItem?.suppressed || false;
    this.logger.debug('Syncing finding table data...', {
      remediationStatus: remediationStatus,
      suppressed: suppressed,
      findingId: finding.Id,
      isFull,
    });

    let findingTableItem: FindingTableItem;
    try {
      findingTableItem = this.buildFindingTableItem(
        finding,
        sanitizedFindingId,
        sanitizedControlId,
        suppressed,
        remediationStatus,
      );
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
