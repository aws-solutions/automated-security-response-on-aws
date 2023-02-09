// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveVPCDefaultSecurityGroupRulesDocument(scope, id, { ...props, controlId: 'EC2.2' });
}

export class RemoveVPCDefaultSecurityGroupRulesDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.2',
      remediationName: 'RemoveVPCDefaultSecurityGroupRules',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'GroupId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group\/(sg-[0-9a-f]*)$`,
      updateDescription: HardCodedString.of('Removed rules on default security group'),
    });
  }
}
