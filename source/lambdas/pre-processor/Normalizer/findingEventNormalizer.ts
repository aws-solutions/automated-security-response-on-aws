// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  ASFFSchema,
  OCSFComplianceSchema,
  ASFFFinding,
  OCSFComplianceFinding,
  ASFFComplianceStatus,
  ASFFSeverity,
  ASFFRecordState,
  ASFFWorkflowStatus,
  InvalidFindingSchemaError,
} from '@asr/data-models';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { Logger } from '@aws-lambda-powertools/logger';

enum FindingSchema {
  OCSF = 'OCSF', // Open Cybersecurity FindingSchema Framework
  ASFF = 'ASFF', // AWS Security Finding Format
  UNKNOWN = 'UNKNOWN',
}

// amazonq-ignore-next-line
const FINDING_ID_PATTERNS = [
  { regex: /(security-control\/[^/]+)\/finding/, findingType: 'consolidated' },
  { regex: /subscription\/([^/]+\/v\/[^/]+\/[^/]+)\/finding/, findingType: 'unconsolidated' },
];

export class FindingEventNormalizer {
  private readonly logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /** Convert OCSF compliance status to ASFF format */
  private getASFFComplianceStatus(ocsfStatus: string | undefined): ASFFComplianceStatus {
    if (!ocsfStatus) return 'NOT_AVAILABLE';

    const statusMap: Record<string, ASFFComplianceStatus> = {
      pass: 'PASSED',
      fail: 'FAILED',
      warning: 'WARNING',
    };

    const lowercaseStatus = ocsfStatus.toLowerCase();
    return statusMap[lowercaseStatus] || 'NOT_AVAILABLE';
  }

  /** Convert OCSF severity to ASFF format */
  private getASFFSeverity(ocsfSeverity: string | undefined): ASFFSeverity {
    if (!ocsfSeverity) return 'INFORMATIONAL';

    const severityMap: Record<string, ASFFSeverity> = {
      low: 'LOW',
      medium: 'MEDIUM',
      high: 'HIGH',
      critical: 'CRITICAL',
      fatal: 'CRITICAL', // the highest severity in ASFF is critical
    };

    return severityMap[ocsfSeverity.toLowerCase()] ?? 'INFORMATIONAL';
  }

  /** Convert OCSF activity ID to ASFF record state */
  private getASFFRecordState(ocsfActivityId: number, ocsfStatusId?: number): ASFFRecordState {
    const ARCHIVED_ACTIVITY_ID = 3;
    const ARCHIVED_STATUS_ID = 5;
    if (ocsfActivityId === ARCHIVED_ACTIVITY_ID || ocsfStatusId === ARCHIVED_STATUS_ID) {
      return 'ARCHIVED';
    } else {
      return 'ACTIVE';
    }
  }

  /** Convert OCSF status ID to ASFF workflow status */
  private getASFFWorkflowStatus(ocsfStatusId: number | undefined): ASFFWorkflowStatus {
    if (ocsfStatusId === undefined) return 'NEW';

    const statusMap: Record<number, ASFFWorkflowStatus> = {
      0: 'NEW',
      1: 'NEW',
      2: 'NOTIFIED',
      3: 'SUPPRESSED',
    };

    return statusMap[ocsfStatusId] ?? 'RESOLVED';
  }

  /** Extract standard ID from OCSF finding ID */
  private getFindingStandardId(ocsfFindingId: string): string {
    // captures the standardId from the findingId — for example, if the ARN is arn:aws:securityhub:us-east-1:123456789012:subscription/aws-resource-tagging-standard/v/1.0.0/IAM.24/finding/x
    // then findingStandardId will be "aws-resource-tagging-standard/v/1.0.0/IAM.24"
    for (const { regex, findingType } of FINDING_ID_PATTERNS) {
      const match = ocsfFindingId.match(regex);
      if (match) return match[1];
      else
        this.logger.debug(`OCSF findingId does not match expected pattern for ${findingType} findings.`, {
          findingId: ocsfFindingId,
          expectedPattern: regex,
        });
    }
    throw new Error(`Failed to parse security standard ID from OCSF findingId ${ocsfFindingId}`);
  }

  /** Generate standards control ARN from OCSF finding */
  private generateStandardsControlArn(ocsfFinding: OCSFComplianceFinding): string | undefined {
    const ocsfFindingId = ocsfFinding.finding_info.uid;
    // consolidated findings do not require the StandardsControlArn to be set
    if (ocsfFindingId.includes('security-control')) {
      return undefined;
    }
    try {
      const unconsolidatedPattern = FINDING_ID_PATTERNS.find((pattern) => pattern.findingType === 'unconsolidated');
      if (!unconsolidatedPattern?.regex.test(ocsfFindingId)) {
        this.logger.debug(
          'OCSF findingId does not match expected pattern - standards control ARN will not be included in ASFF ProductFields.',
          {
            findingId: ocsfFindingId,
            expectedPattern: { regex: unconsolidatedPattern?.regex.source, type: 'Unconsolidated Finding ID' },
          },
        );
        return undefined;
      }

      const findingIdSplit = ocsfFindingId.split(':');

      const partition = findingIdSplit[1];
      const findingRegion = findingIdSplit[3];
      const findingAccountId = findingIdSplit[4];
      const findingStandardId = this.getFindingStandardId(ocsfFindingId);

      return `arn:${partition}:securityhub:${findingRegion}:${findingAccountId}:control/${findingStandardId}`;
    } catch (error) {
      this.logger.debug(
        'Failed to generate standards control ARN from OCSF finding_info.uid - standards control ARN will not be included in ASFF ProductFields.',
        {
          findingId: ocsfFinding.finding_info.uid,
          error: error,
        },
      );
      return undefined;
    }
  }

  private async parseSchema(finding: Record<any, any>): Promise<FindingSchema> {
    const ocsfResult = OCSFComplianceSchema.safeParse(finding);
    const asffResult = ASFFSchema.safeParse(finding);
    let schemaResult: FindingSchema;

    if (ocsfResult.success) {
      schemaResult = FindingSchema.OCSF;
      await sendMetrics({ finding_schema: 'OCSF' });
    } else if (asffResult.success) {
      schemaResult = FindingSchema.ASFF;
      await sendMetrics({ finding_schema: 'ASFF' });
    } else {
      this.logger.warn(
        `FindingSchema type could not be resolved for finding. FindingSchema must be one of ${Object.values(
          FindingSchema,
        )
          .filter((s) => s !== FindingSchema.UNKNOWN)
          .join(' or ')}`,
        {
          finding: finding,
          ocsfErrors: ocsfResult.error,
          asffErrors: asffResult.error,
        },
      );
      await sendMetrics({ finding_schema: 'unknown' });
      throw new InvalidFindingSchemaError(Object.values(FindingSchema).filter((s) => s !== FindingSchema.UNKNOWN));
    }
    this.logger.debug(`Finding FindingSchema: ${schemaResult}`);
    return schemaResult;
  }

  /** Normalize finding to ASFF format */
  async normalizeFinding(finding: Record<any, any>): Promise<ASFFFinding> {
    const findingSchema = await this.parseSchema(finding);

    if (findingSchema === FindingSchema.ASFF) {
      this.logger.debug('Finding is already in ASFF, skipping normalization...');
      return finding as ASFFFinding;
    } else if (findingSchema === FindingSchema.OCSF) {
      this.logger.debug('Finding is OCSF, starting normalization...');

      return this.normalizeOCSFFinding(finding as OCSFComplianceFinding);
    } else {
      throw new Error(`Finding FindingSchema is not OCSF or ASFF.`);
    }
  }

  /** Convert OCSF finding to ASFF format */
  private normalizeOCSFFinding(ocsfFinding: OCSFComplianceFinding): ASFFFinding {
    const standardId = this.getFindingStandardId(ocsfFinding.finding_info.uid);
    const standardsControlArn = this.generateStandardsControlArn(ocsfFinding);

    return {
      SchemaVersion: '2018-10-08',
      Id: ocsfFinding.finding_info.uid,
      ProductArn: ocsfFinding.metadata?.product?.uid ?? '',
      ProductName: ocsfFinding.metadata?.product?.name,
      GeneratorId: standardId,
      RecordState: this.getASFFRecordState(ocsfFinding.activity_id, ocsfFinding.status_id),
      AwsAccountId: ocsfFinding.cloud.account.uid,
      Region: ocsfFinding.cloud.region,
      Types: ocsfFinding.finding_info.types ?? [''],
      FirstObservedAt: ocsfFinding.finding_info.first_seen_time_dt,
      LastObservedAt: ocsfFinding.finding_info.last_seen_time_dt,
      CreatedAt: ocsfFinding.finding_info.created_time_dt ?? '',
      CompanyName: ocsfFinding.metadata?.product?.vendor_name,
      Workflow: {
        Status: this.getASFFWorkflowStatus(ocsfFinding.status_id),
      },
      FindingProviderFields: this.getNormalizedFindingProviderFields(ocsfFinding),
      Severity: {
        Label: this.getASFFSeverity(ocsfFinding.severity),
      },
      UpdatedAt: ocsfFinding.finding_info.modified_time_dt ?? new Date().toISOString(),
      Title: ocsfFinding.finding_info.title ?? '',
      Description: ocsfFinding.finding_info.desc,
      Remediation: this.getNormalizedRemediation(ocsfFinding),
      Compliance: this.getNormalizedCompliance(ocsfFinding),
      ProductFields: this.getNormalizedProductFields(ocsfFinding, standardsControlArn),
      Resources: this.getNormalizedResources(ocsfFinding),
    };
  }

  /** Extract finding provider fields from OCSF finding */
  private getNormalizedFindingProviderFields(ocsfFinding: OCSFComplianceFinding) {
    return {
      Types: ocsfFinding.finding_info.types,
      Severity: {
        Label: this.getASFFSeverity(ocsfFinding.severity),
      },
    };
  }

  /** Extract remediation data from OCSF finding */
  private getNormalizedRemediation(ocsfFinding: OCSFComplianceFinding) {
    return {
      Recommendation: {
        Text: ocsfFinding.remediation?.desc,
      },
    };
  }

  /** Extract compliance data from OCSF finding */
  private getNormalizedCompliance(ocsfFinding: OCSFComplianceFinding) {
    return {
      Status: this.getASFFComplianceStatus(ocsfFinding.compliance.status),
      SecurityControlId: ocsfFinding.compliance.control,
      RelatedRequirements: ocsfFinding.compliance.requirements,
      AssociatedStandards: ocsfFinding.compliance.standards.map((standardId) => ({ StandardsId: standardId })),
    };
  }

  private getResourceIdFromUids(
    resourceUid: string | undefined,
    resourceUidAlt: string | undefined,
    name: string | undefined,
  ): string {
    /**
     * Takes the `uid_alt`, `uid` and `name` attribute values from an OCSF finding and returns an identifier (usually an ARN) based on the following priority:
     * 1. uid_alt (if it is an ARN)
     * 2. uid
     * 3. name
     *
     * `uid_alt` is the ARN of the resource in most cases, however for some finding types (e.g.CloudFormation.2)
     * this attribute is not present and the ARN is instead stored in the `uid` field instead.
     */
    if (resourceUidAlt?.startsWith('arn:')) {
      return resourceUidAlt;
    }

    return resourceUid ?? name!; // at least one of uid_alt, uid, or name must be defined
  }

  /** Extract product fields from OCSF finding */
  private getNormalizedProductFields(ocsfFinding: OCSFComplianceFinding, standardsControlArn: string | undefined) {
    return {
      'RelatedAWSResources:0/name': ocsfFinding.finding_info.analytic?.name ?? 'unknown',
      'RelatedAWSResources:0/type': ocsfFinding.finding_info.analytic?.category ?? 'unknown',
      'aws/securityhub/ProductName': ocsfFinding.metadata?.product?.name ?? 'unknown',
      'aws/securityhub/findingId': ocsfFinding.finding_info.uid,
      ...(standardsControlArn && { StandardsControlArn: standardsControlArn }),
      ...Object.fromEntries(
        ocsfFinding.resources?.map((resource, index: number) => [
          `Resources:${index}/Id`,
          this.getResourceIdFromUids(resource.uid, resource.uid_alt, resource.name),
        ]) ?? [],
      ),
    };
  }

  /** Extract and normalize resource data from OCSF finding */
  private getNormalizedResources(ocsfFinding: OCSFComplianceFinding) {
    return ocsfFinding.resources.map((resource) => ({
      Type: resource.type,
      Id: this.getResourceIdFromUids(resource.uid, resource.uid_alt, resource.name),
      Partition: resource.cloud_partition,
      Region: resource.region,
      Tags: resource.tags
        ? Object.fromEntries(resource.tags.map((tag: Record<string, string | undefined>) => [tag.name, tag.value]))
        : undefined,
    }));
  }
}
