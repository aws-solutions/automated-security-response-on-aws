// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CloudTrail_5_ControlRunbookDocument } from '../../SC/ssmdocs/SC_CloudTrail.5';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CloudTrail_5_ControlRunbookDocument(stage, id, { ...props, controlId: '3.4' });
}
