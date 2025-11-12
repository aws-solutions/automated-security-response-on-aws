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

  if (
    statusUpper === 'FAILED' ||
    statusUpper === 'ASSUME_ROLE_FAILURE' ||
    statusUpper === 'LAMBDA_ERROR' ||
    statusUpper === 'RUNBOOK_NOT_ACTIVE' ||
    statusUpper === 'NO_RUNBOOK' ||
    statusUpper === 'PLAYBOOK_NOT_ENABLED' ||
    statusUpper === 'TIMEOUT' ||
    statusUpper === 'CANCELLED' ||
    statusUpper === 'ABORTED'
  ) {
    return 'FAILED';
  }

  return 'FAILED';
}
