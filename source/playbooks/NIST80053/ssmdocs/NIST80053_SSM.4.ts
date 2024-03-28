// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { DisablePublicSSMDocument } from '../../SC/ssmdocs/SC_SSM.4';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicSSMDocument(scope, id, { ...props, controlId: 'SSM.4' });
}
