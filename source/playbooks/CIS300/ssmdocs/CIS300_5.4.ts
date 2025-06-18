// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { RemoveVPCDefaultSecurityGroupRulesDocument } from '../../SC/ssmdocs/SC_EC2.2';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveVPCDefaultSecurityGroupRulesDocument(stage, id, { ...props, controlId: '5.4' });
}
