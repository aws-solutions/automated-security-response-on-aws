// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import {
  AutomationStep,
  DataTypeEnum,
  ExecuteScriptStep,
  HardCodedString,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringFormat,
  StringMapVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new IAMAccessAnalyzerExternalAccessDocument(scope, id, {
    ...props,
    controlId: 'IAMAccessAnalyzer.ExternalAccess',
  });
}

export class IAMAccessAnalyzerExternalAccessDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'IAMAccessAnalyzer.ExternalAccess',
      remediationName: 'TightenResourcePolicy',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ResourceArn',
      resourceIdRegex: String.raw`^(arn:(?:aws|aws-cn|aws-us-gov):.+)$`,
      updateDescription: HardCodedString.of(
        'Tightened resource policy to remove wildcard principals and restrict access to the owning account and organization.',
      ),
      // Override the document name to use multi-service naming pattern
      documentName: `${props.solutionAcronym}-IAMAccessAnalyzer.ExternalAccess`,
    });
  }

  /** Override ParseInput to extract resource ARN and type from ASFF finding. */
  protected override getParseInputStep(): AutomationStep {
    return new ExecuteScriptStep(this, 'ParseInput', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'parse_event'),
      code: ScriptCode.fromFile(
        fs.realpathSync(path.join(__dirname, 'scripts', 'SC_IAMAccessAnalyzer.ExternalAccess_parse.py')),
      ),
      inputPayload: {
        Finding: StringMapVariable.of('Finding'),
      },
      outputs: this.getParseInputStepOutputs(),
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
        name: 'ResourceArn',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.resource_arn',
      },
      {
        name: 'ResourceType',
        outputType: DataTypeEnum.STRING,
        selector: '$.Payload.resource_type',
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
    ];
  }

  protected override getRemediationParams(): Record<string, any> {
    return {
      AutomationAssumeRole: new StringFormat('arn:%s:iam::%s:role/%s', [
        StringVariable.of('global:AWS_PARTITION'),
        StringVariable.of('global:ACCOUNT_ID'),
        StringVariable.of('RemediationRoleName'),
      ]),
      ResourceArn: StringVariable.of('ParseInput.ResourceArn'),
      ResourceType: StringVariable.of('ParseInput.ResourceType'),
    };
  }
}
