// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableIMDSV2OnInstance(scope, id, { ...props, controlId: 'EC2.8' });
}

export class EnableIMDSV2OnInstance extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.8',
      remediationName: 'EnableIMDSV2OnInstance',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'InstanceARN',
      updateDescription: HardCodedString.of('Enabled IMDSv2 on Instance'),
    });
  }
}
