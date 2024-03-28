// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from '../../SC/ssmdocs/control_runbook';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisableUnrestrictedAccessToHighRiskPortsDocument(stage, id, { ...props, controlId: 'EC2.19' });
}

export class DisableUnrestrictedAccessToHighRiskPortsDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'EC2.19',
      remediationName: 'DisableUnrestrictedAccessToHighRiskPorts',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'SecurityGroupId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group/(sg-[0-9a-f]*)$`,
      updateDescription: HardCodedString.of('Revoking access to high risk ports.'),
    });
  }
}
