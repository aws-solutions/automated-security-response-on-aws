// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { remediationStatus } from '@asr/data-models';

export function mapRemediationStatus(status: string | undefined): remediationStatus {
  if (!status) {
    return 'NOT_STARTED';
  }

  const statusUpper = status.toUpperCase();

  if (statusUpper === 'SUCCESS') {
    return 'SUCCESS';
  }

  if (statusUpper === 'NOT_STARTED') {
    return 'NOT_STARTED';
  }

  if (statusUpper === 'IN_PROGRESS' || statusUpper === 'QUEUED' || statusUpper === 'RUNNING') {
    return 'IN_PROGRESS';
  }

  if (statusUpper === 'ROLLBACK_IN_PROGRESS') {
    return 'ROLLBACK_IN_PROGRESS';
  }

  if (statusUpper === 'ROLLBACK_SUCCESS') {
    return 'ROLLBACK_SUCCESS';
  }

  if (statusUpper === 'ROLLBACK_FAILED') {
    return 'ROLLBACK_FAILED';
  }

  // Known failure states — listed explicitly so the warn below only fires for
  // genuinely unexpected values from new upstream sources.
  if (
    statusUpper === 'FAILED' ||
    statusUpper === 'ASSUME_ROLE_FAILURE' ||
    statusUpper === 'LAMBDA_ERROR' ||
    statusUpper === 'RUNBOOK_NOT_ACTIVE' ||
    statusUpper === 'NO_RUNBOOK' ||
    statusUpper === 'PLAYBOOK_NOT_ENABLED' ||
    statusUpper === 'TIMEOUT' ||
    statusUpper === 'TIMEDOUT' ||
    statusUpper === 'TIMED_OUT' ||
    statusUpper === 'CANCELLED' ||
    statusUpper === 'CANCELLING' ||
    statusUpper === 'ABORTED'
  ) {
    return 'FAILED';
  }

  console.warn('Unknown remediation status, defaulting to FAILED', { status });
  return 'FAILED';
}
