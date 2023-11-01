// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveUnrestrictedSourceIngressRules(scope, id, { ...props, controlId: 'EC2.19' });
}

export class RemoveUnrestrictedSourceIngressRules extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.19',
      remediationName: 'RemoveUnrestrictedSourceIngressRules',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SecurityGroupId',
      updateDescription: HardCodedString.of('Removes all ingress rules from the security group you specify that allow traffic from all source addresse.'),
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group\/(sg-[0-9a-f]*)$`
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();
    return params;
  }
}
