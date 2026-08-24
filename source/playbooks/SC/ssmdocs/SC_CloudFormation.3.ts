// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// AIGenerated: true
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCFNTerminationProtection(scope, id, { ...props, controlId: 'CloudFormation.3' });
}

export class EnableCFNTerminationProtection extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'CloudFormation.3',
      remediationName: 'EnableCFNTerminationProtection',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'StackArn',
      resourceIdRegex: String.raw`^(arn:(?:aws|aws-us-gov|aws-cn):cloudformation:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:stack/[a-zA-Z][a-zA-Z0-9-]{0,127}/[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12})$`,
      updateDescription: HardCodedString.of('Enabled termination protection for CloudFormation stack.'),
    });
  }
}
