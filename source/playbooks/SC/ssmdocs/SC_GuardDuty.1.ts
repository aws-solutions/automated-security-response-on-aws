// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableGuardDutyDocument(stage, id, { ...props, controlId: 'GuardDuty.1' });
}

export class EnableGuardDutyDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'GuardDuty.1',
      remediationName: 'EnableGuardDuty',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Amazon GuardDuty enabled.'),
    });
  }
}
