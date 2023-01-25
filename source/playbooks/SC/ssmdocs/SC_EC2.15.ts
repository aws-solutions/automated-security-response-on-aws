// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EC2_15_ControlRunbookDocument(scope, id, { ...props, controlId: 'EC2.15' });
}

export class EC2_15_ControlRunbookDocument extends ControlRunbookDocument {
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

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();
    return params;
  }
}