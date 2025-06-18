// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { AttachServiceVPCEndpointDocument } from '../../SC/ssmdocs/SC_EC2.10';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new AttachServiceVPCEndpointDocument(scope, id, { ...props, controlId: 'EC2.10' });
}
