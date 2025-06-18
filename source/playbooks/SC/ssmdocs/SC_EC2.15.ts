// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicIPAutoAssignDocument(scope, id, { ...props, controlId: 'EC2.15' });
}

export class DisablePublicIPAutoAssignDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.15',
      remediationName: 'DisablePublicIPAutoAssign',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SubnetARN',
      updateDescription: HardCodedString.of('Disabled public IP auto assignment for subnet.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();
    return params;
  }
}
