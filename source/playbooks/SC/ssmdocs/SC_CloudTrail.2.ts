// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, Input, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

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
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TrailArn',
      updateDescription: HardCodedString.of('Encryption enabled on CloudTrail'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();
    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.TrailRegion = StringVariable.of('ParseInput.RemediationRegion');

    return params;
  }
}
