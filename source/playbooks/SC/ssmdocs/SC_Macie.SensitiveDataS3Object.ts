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
  ExecuteScriptStep,
  HardCodedString,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringMapVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new MacieSensitiveDataS3ObjectDocument(scope, id, {
    ...props,
    controlId: 'Macie.SensitiveDataS3Object',
  });
}

export class MacieSensitiveDataS3ObjectDocument extends SingleStepControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Macie.SensitiveDataS3Object',
      remediationName: 'Macie.SensitiveDataS3Object',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'BucketName',
      updateDescription: HardCodedString.of(
        'Enabled S3 Block Public Access on the bucket containing sensitive data detected by Macie as a first-line protection. Manual investigation required.',
      ),
      documentName: `${props.solutionAcronym}-Macie.SensitiveDataS3Object`,
    });
  }

  protected override getParseInputStep(): ExecuteScriptStep {
    return new ExecuteScriptStep(this, 'ParseInput', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'parse_event'),
      code: ScriptCode.fromFile(fs.realpathSync(path.join(__dirname, 'scripts', 'SC_Macie.SensitiveDataS3Object.py'))),
      inputPayload: {
        Finding: StringMapVariable.of('Finding'),
        // Per-control role assumed by parse_event for the privileged
        // s3:PutBucketPublicAccessBlock and securityhub:BatchUpdateFindings
        // calls. The runbook's AutomationAssumeRole does not carry these.
        RemediationRoleName: StringVariable.of('RemediationRoleName'),
        SSMDocName: HardCodedString.of(this.documentName),
      },
      outputs: this.getParseInputStepOutputs(),
      // s3:PutPublicAccessBlock is a fast synchronous call — 60s is more than sufficient.
      timeoutSeconds: 60,
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
        name: 'BucketName',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.bucket_name',
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
    ];
  }
}
