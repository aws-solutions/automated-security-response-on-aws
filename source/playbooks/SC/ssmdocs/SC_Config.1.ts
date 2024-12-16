// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, Input, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAWSConfigDocument(scope, id, { ...props, controlId: 'Config.1' });
}

export class EnableAWSConfigDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs: Input[] = [
      Input.ofTypeString('KMSKeyArn', {
        description: `The ARN of the KMS key created by ${props.solutionAcronym} for remediations`,
        defaultValue: `{{ssm:/Solutions/${props.solutionId}/CMK_REMEDIATION_ARN}}`,
        allowedPattern: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(?:(?:alias\/[A-Za-z0-9/-_])|(?:key\/(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})))$`,
      }),
    ];

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'Config.1',
      remediationName: 'EnableAWSConfig',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('AWS Config enabled'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.SNSTopicName = `${this.solutionId}-SHARR-AWSConfigNotification`;
    params.KMSKeyArn = StringVariable.of('KMSKeyArn');

    return params;
  }
}
