// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { inflate } from 'pako';
import { ACTION_TYPE_TO_ASR_ACTION_NAME, MULTI_SERVICE_REMEDIATION_IDS } from '@asr/data-models';
import type { ASFFFinding, FindingTableItem } from '@asr/data-models';
import type { Clock } from './clock';
import { ErrorUtils } from './errorUtils';
import type { IdGenerator } from './idGenerator';

export function extractASFFFinding(findingTableItem: FindingTableItem): ASFFFinding {
  try {
    if (!findingTableItem.findingJSON) {
      throw new Error('No findingJSON data available');
    }
    const decompressed = inflate(findingTableItem.findingJSON, { to: 'string' });
    // findingJSON is pre-validated at ingestion time by the pre-processor Lambda
    return JSON.parse(decompressed) as ASFFFinding;
  } catch (error) {
    throw new Error(`Failed to extract ASFF finding: ${ErrorUtils.formatErrorMessage(error)}`);
  }
}

export function buildOrchestratorInput(
  remediationId: string,
  asffFinding: ASFFFinding,
  actionType: keyof typeof ACTION_TYPE_TO_ASR_ACTION_NAME,
  idGenerator: IdGenerator,
  clock: Clock,
  rollbackBackupKey?: string,
): string {
  const actionName = ACTION_TYPE_TO_ASR_ACTION_NAME[actionType];
  const isMultiService = MULTI_SERVICE_REMEDIATION_IDS.has(remediationId);

  return JSON.stringify({
    version: '0',
    id: idGenerator.randomUUID(),
    'detail-type': 'Security Hub Findings - API Action',
    source: 'aws.securityhub',
    account: asffFinding.AwsAccountId,
    region: asffFinding.Region,
    time: clock.now().toISOString(),
    resources: [
      `arn:aws:securityhub:${asffFinding.Region}:${asffFinding.AwsAccountId}:action/custom/api-${actionType.toLowerCase()}`,
    ],
    detail: {
      findings: [asffFinding],
      actionName,
      actionDescription: `API-triggered ${actionType}`,
      // Mirror the multi-service Detail envelope the PreProcessor already
      // emits for auto-triggered findings (see preProcessor.buildOrchestratorInput):
      // `findingType: 'multiService'` is the Orchestrator's routing
      // discriminator (resolve_ssm_doc_for_finding branches on it), while
      // `remediationId` carries the specific control (e.g. GuardDuty.IAMUser).
      // Omitting them sends the finding down the SH-standard path, which
      // resolves an empty document name. The API always ships the ASFF
      // representation read back from the table, so findingFormat is always
      // ASFF here even when the source ingestion was OCSF.
      ...(isMultiService && {
        findingType: 'multiService',
        remediationId,
        findingFormat: 'ASFF',
      }),
      // Rollback runs the GuardDuty runbook with Action=Restore and must pass
      // back the exact S3 key of the Contain backup; the managed runbook cannot
      // derive it. Both flow through exec_ssm_doc's docParameters allowlist.
      ...(actionType === 'Rollback' && {
        docParameters: {
          Action: 'Restore',
          ...(rollbackBackupKey ? { BackupS3KeyName: rollbackBackupKey } : {}),
        },
      }),
    },
  });
}
