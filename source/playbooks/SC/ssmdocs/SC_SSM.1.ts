// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new AttachSSMPermissionsToEC2(scope, id, { ...props, controlId: 'SSM.1' });
}

export class AttachSSMPermissionsToEC2 extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SSM.1',
      remediationName: 'AttachSSMPermissionsToEC2',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'InstanceArn',
      updateDescription: HardCodedString.of('AmazonSSMManagedInstanceCore IAM Policy attached to EC2 Instance.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.RemediationRole = new StringFormat(
      `arn:%s:iam::%s:role/${this.solutionId}-AttachSSMPermissionsToEC2-RemediationRole-${this.namespace}`,
      [StringVariable.of('global:AWS_PARTITION'), StringVariable.of('global:ACCOUNT_ID')],
    );

    params.InstanceProfile = new StringFormat(
      `${this.solutionId}-AttachSSMPermissionsToEC2-InstanceProfile-${this.namespace}`,
    );

    return params;
  }
}
