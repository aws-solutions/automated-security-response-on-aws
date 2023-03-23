// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CreateLogMetricFilterAndAlarmDocument } from '../../SC/ssmdocs/SC_CloudWatch.1';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CreateLogMetricFilterAndAlarmDocument(stage, id, {
    ...props,
    controlId: '4.1',
    otherControlIds: ['4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9', '4.10', '4.11', '4.12', '4.13', '4.14'],
  });
}
