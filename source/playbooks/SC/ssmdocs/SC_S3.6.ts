// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  ExecuteScriptStep,
  HardCodedString,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new S3BlockDenylistDocument(scope, id, { ...props, controlId: 'S3.6' });
}

export class S3BlockDenylistDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.6',
      remediationName: 'S3BlockDenylist',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Added explicit deny for sensitive bucket access from another account.'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DenyListSerialized',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.aws_config_rule.InputParameters',
    });

    outputs.push({
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    return outputs;
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      new ExecuteScriptStep(this, 'ExtractSensitiveApis', {
        language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'runbook_handler'),
        code: ScriptCode.fromFile(
          fs.realpathSync(path.join(__dirname, '..', '..', 'AFSBP', 'ssmdocs', 'scripts', 'deserializeApiList.py')),
        ),
        outputs: [
          {
            name: 'ListOfApis',
            outputType: DataTypeEnum.STRING,
            selector: '$.Payload',
          },
        ],
        inputPayload: {
          SerializedList: StringVariable.of('ParseInput.DenyListSerialized'),
        },
      }),
    ];
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DenyList = StringVariable.of('ExtractSensitiveApis.ListOfApis');

    return params;
  }
}
