// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Input, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudTrailEncryptionDocument(scope, id, { ...props, controlId: 'CloudTrail.2' });
}

export class EnableCloudTrailEncryptionDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs = [
      Input.ofTypeString('KMSKeyArn', {
        allowedPattern: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(?:(?:alias\/[A-Za-z0-9/_-])|(?:key\/(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})))$`,
        defaultValue: '{{ssm:/Solutions/SO0111/CMK_REMEDIATION_ARN}}',
      }),
    ];

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'CloudTrail.2',
      remediationName: 'EnableCloudTrailEncryption',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'TrailArn',
      updateDescription: HardCodedString.of('Encryption enabled on CloudTrail'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RemediationRegion',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource_region',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.TrailRegion = StringVariable.of('ParseInput.RemediationRegion');
    params.KMSKeyArn = StringVariable.of('KMSKeyArn');

    return params;
  }
}
