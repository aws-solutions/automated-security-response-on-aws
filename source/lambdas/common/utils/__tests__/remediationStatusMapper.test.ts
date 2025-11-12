// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mapRemediationStatus } from '../remediationStatusMapper';

describe('mapRemediationStatus', () => {
  it('should return NOT_STARTED for undefined status', () => {
    expect(mapRemediationStatus(undefined)).toBe('NOT_STARTED');
  });

  it('should return NOT_STARTED for empty string', () => {
    expect(mapRemediationStatus('')).toBe('NOT_STARTED');
  });

  it('should map SUCCESS correctly', () => {
    expect(mapRemediationStatus('SUCCESS')).toBe('SUCCESS');
    expect(mapRemediationStatus('success')).toBe('SUCCESS');
  });

  it('should map IN_PROGRESS statuses correctly', () => {
    expect(mapRemediationStatus('IN_PROGRESS')).toBe('IN_PROGRESS');
    expect(mapRemediationStatus('QUEUED')).toBe('IN_PROGRESS');
    expect(mapRemediationStatus('RUNNING')).toBe('IN_PROGRESS');
    expect(mapRemediationStatus('queued')).toBe('IN_PROGRESS');
    expect(mapRemediationStatus('running')).toBe('IN_PROGRESS');
  });

  it('should map FAILED statuses correctly', () => {
    expect(mapRemediationStatus('FAILED')).toBe('FAILED');
    expect(mapRemediationStatus('ASSUME_ROLE_FAILURE')).toBe('FAILED');
    expect(mapRemediationStatus('LAMBDA_ERROR')).toBe('FAILED');
    expect(mapRemediationStatus('RUNBOOK_NOT_ACTIVE')).toBe('FAILED');
    expect(mapRemediationStatus('NO_RUNBOOK')).toBe('FAILED');
    expect(mapRemediationStatus('PLAYBOOK_NOT_ENABLED')).toBe('FAILED');
    expect(mapRemediationStatus('TIMEOUT')).toBe('FAILED');
    expect(mapRemediationStatus('CANCELLED')).toBe('FAILED');
    expect(mapRemediationStatus('ABORTED')).toBe('FAILED');
    expect(mapRemediationStatus('failed')).toBe('FAILED');
    expect(mapRemediationStatus('timeout')).toBe('FAILED');
  });

  it('should map NOT_STARTED correctly', () => {
    expect(mapRemediationStatus('NOT_STARTED')).toBe('NOT_STARTED');
    expect(mapRemediationStatus('not_started')).toBe('NOT_STARTED');
  });

  it('should handle case insensitive mapping', () => {
    expect(mapRemediationStatus('Success')).toBe('SUCCESS');
    expect(mapRemediationStatus('Failed')).toBe('FAILED');
    expect(mapRemediationStatus('In_Progress')).toBe('IN_PROGRESS');
  });
});
