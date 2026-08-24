// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  ControlRunbookDocument,
  ControlRunbookProps,
  RemediationScope,
  SingleStepControlRunbookDocument,
} from './control_runbook';
import {
  DataTypeEnum,
  DocumentOutput,
  ExecuteScriptStep,
  HardCodedString,
  Input,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringMapVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new GuardDutyIAMUserDocument(scope, id, {
    ...props,
    controlId: 'GuardDuty.IAMUser',
  });
}

export class GuardDutyIAMUserDocument extends SingleStepControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'GuardDuty.IAMUser',
      remediationName: 'GuardDuty.IAMUser',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'UserName',
      updateDescription: HardCodedString.of(
        'Contained compromised IAM user credentials using AWSSupport-ContainIAMPrincipal as a short-term mitigation. Manual review of the finding is required to determine the long-term fix.',
      ),
      documentName: `${props.solutionAcronym}-GuardDuty.IAMUser`,
      docInputs: [
        Input.ofTypeString('Action', {
          description: 'Action to perform: Contain (default) or Restore.',
          defaultValue: 'Contain',
          allowedValues: ['Contain', 'Restore'],
        }),
        Input.ofTypeString('RemediationConfigBucket', {
          description: 'S3 bucket name for IAM configuration backups (used by AWSSupport-ContainIAMPrincipal).',
          defaultValue: '{{ssm:/Solutions/SO0111/RemediationConfigurationBucket}}',
        }),
        Input.ofTypeString('BackupS3KeyName', {
          description:
            'Required only for Restore: the exact S3 object key of the backup written by the original Contain ' +
            'execution. AWSSupport-ContainIAMPrincipal cannot derive it. Left empty for Contain.',
          defaultValue: '',
        }),
      ],
    });
  }

  protected override getAdditionalDocumentOutputs(): DocumentOutput[] {
    // Surface the captured backup S3 key at the document level so the
    // Orchestrator (check_ssm_execution) can read ParseInput.BackupS3Key from
    // GetAutomationExecution.Outputs and thread it to a later Restore.
    return [{ name: 'ParseInput.BackupS3Key', outputType: DataTypeEnum.STRING }];
  }

  protected override getParseInputStep(): ExecuteScriptStep {
    return new ExecuteScriptStep(this, 'ParseInput', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'parse_event'),
      code: ScriptCode.fromFile(fs.realpathSync(path.join(__dirname, 'scripts', 'SC_GuardDuty.IAMUser.py'))),
      inputPayload: {
        Finding: StringMapVariable.of('Finding'),
        Action: StringVariable.of('Action'),
        RemediationConfigBucket: StringVariable.of('RemediationConfigBucket'),
        RemediationRoleName: StringVariable.of('RemediationRoleName'),
        BackupS3KeyName: StringVariable.of('BackupS3KeyName'),
        SSMDocName: HardCodedString.of(this.documentName),
      },
      outputs: this.getParseInputStepOutputs(),
      // The Python script polls GetAutomationExecution until AWSSupport-ContainIAMPrincipal
      // reaches a terminal state (MAX_POLL_DURATION_SECONDS = 600s, ~10 min).
      // This timeout must exceed that polling window plus invocation overhead.
      timeoutSeconds: 720,
      isEnd: true,
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    return [
      {
        name: 'FindingId',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.finding_id',
      },
      {
        name: 'ProductArn',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.product_arn',
      },
      {
        name: 'AffectedObject',
        outputType: DataTypeEnum.STRING_MAP,
        selector: '$.Payload.object',
      },
      {
        name: 'UserName',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.user_name',
      },
      {
        name: 'RemediationAccount',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.account_id',
      },
      {
        name: 'RemediationRegion',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.resource_region',
      },
      {
        name: 'Status',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.status',
      },
      {
        name: 'Message',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.message',
      },
      {
        name: 'BackupS3Key',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.backup_s3_key',
      },
    ];
  }
}
