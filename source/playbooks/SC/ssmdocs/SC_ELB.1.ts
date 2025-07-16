// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnforceHTTPSForALB(scope, id, { ...props, controlId: 'ELB.1' });
}

export class EnforceHTTPSForALB extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'ELB.1',
      remediationName: 'EnforceHTTPSForALB',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ResourceARN',
      updateDescription: new StringFormat('HTTP redirect configured for ALB %s.', [
        StringVariable.of(`ParseInput.ResourceARN`),
      ]),
    });
  }
}
