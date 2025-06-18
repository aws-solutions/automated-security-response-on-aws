// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  AwsApiStep,
  AwsService,
  BranchStep,
  Choice,
  DataTypeEnum,
  ExecuteScriptStep,
  HardCodedString,
  Operation,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableRedshiftClusterAuditLoggingDocument(scope, id, { ...props, controlId: 'Redshift.4' });
}

export class EnableRedshiftClusterAuditLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Redshift.4',
      remediationName: 'EnableRedshiftClusterAuditLogging',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ClusterIdentifier',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):redshift:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:cluster:(?!.*--)([a-z][a-z0-9-]{0,62})(?<!-)$`,
      updateDescription: HardCodedString.of('Enabled Audit logging for the Redshift cluster.'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RetentionPeriodSerialized',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.aws_config_rule.InputParameters',
    });

    return outputs;
  }

  protected override getExtraSteps(): AutomationStep[] {
    const checkSsmParamStepName = 'CheckIfSSMParameterWithS3BucketNameIsAvailable';
    const bucketNameOutputName = 'BucketName';
    const updateFindingNotConfiguredStepName = 'UpdateFindingThatS3BucketNameIsNotConfigured';

    return [
      new ExecuteScriptStep(this, checkSsmParamStepName, {
        language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'check_for_s3_bucket_name'),
        code: ScriptCode.fromFile(fs.realpathSync(path.join(__dirname, 'scripts', 'check_for_s3_bucket_name.py'))),
        outputs: [
          {
            name: bucketNameOutputName,
            outputType: DataTypeEnum.STRING,
            selector: '$.Payload.s3_bucket_name_for_redshift_audit_logging',
          },
        ],
        inputPayload: { SerializedJson: StringVariable.of('ParseInput.RetentionPeriodSerialized') },
      }),
      new BranchStep(this, 'ValidateIfS3BucketNameIsConfigured', {
        choices: [
          new Choice({
            operation: Operation.STRING_EQUALS,
            constant: 'NOT_AVAILABLE',
            variable: StringVariable.of(`${checkSsmParamStepName}.${bucketNameOutputName}`),
            jumpToStepName: updateFindingNotConfiguredStepName,
          }),
        ],
        defaultStepName: 'Remediation',
      }),
      new AwsApiStep(this, updateFindingNotConfiguredStepName, {
        service: AwsService.SECURITY_HUB,
        pascalCaseApi: 'BatchUpdateFindings',
        description: 'Abort remediation as s3 bucket name is unavailable.',
        apiParams: {
          FindingIdentifiers: [
            {
              Id: StringVariable.of('ParseInput.FindingId'),
              ProductArn: StringVariable.of('ParseInput.ProductArn'),
            },
          ],
          Note: {
            Text: 'Remediation failed the s3 bucket name is not available, review the cloudformation template and select the option Yes for create redshift.4 s3 bucket cloudformation parameter.',
            UpdatedBy: this.documentName,
          },
          Workflow: { Status: 'NOTIFIED' },
        },
        outputs: [],
        isEnd: true,
      }),
    ];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.BucketName = StringVariable.of('CheckIfSSMParameterWithS3BucketNameIsAvailable.BucketName');

    return params;
  }
}
