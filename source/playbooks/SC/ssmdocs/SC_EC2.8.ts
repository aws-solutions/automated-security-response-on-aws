// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

// EnforceEC2InstanceIMDSv2
export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnforceEC2InstanceIMDSv2(scope, id, { ...props, controlId: 'EC2.8' });
}

export class EnforceEC2InstanceIMDSv2 extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.8',
      remediationName: 'EnforceEC2InstanceIMDSv2',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Enforce EC2instance IMDSv2'),
      resourceIdName: 'InstanceId',
      resourceIdRegex: String.raw`^arn:aws:ec2:[a-z0-9-]+:\d{12}:instance/(i-[0-9a-fA-F]{17})$`
    });
  }
}

