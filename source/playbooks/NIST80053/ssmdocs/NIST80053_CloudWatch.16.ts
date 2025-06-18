// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { SetLogGroupRetentionDaysDocument } from '../../SC/ssmdocs/SC_CloudWatch.16';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetLogGroupRetentionDaysDocument(stage, id, { ...props, controlId: 'CloudWatch.16' });
}
