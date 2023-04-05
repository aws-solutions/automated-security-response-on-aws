// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { CreateLogMetricFilterAndAlarmDocument } from '../../SC/ssmdocs/SC_CloudWatch.1';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CreateLogMetricFilterAndAlarmDocument(stage, id, { ...props, controlId: 'CloudWatch.1', otherControlIds: [
    'CloudWatch.2',
    'CloudWatch.3',
    'CloudWatch.4',
    'CloudWatch.5',
    'CloudWatch.6',
    'CloudWatch.7',
    'CloudWatch.8',
    'CloudWatch.9',
    'CloudWatch.10',
    'CloudWatch.11',
    'CloudWatch.12',
    'CloudWatch.13',
    'CloudWatch.14',
  ] });
}
