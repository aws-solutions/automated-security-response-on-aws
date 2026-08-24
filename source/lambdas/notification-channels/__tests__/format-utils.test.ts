// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  formatSubject,
  formatEventDescription,
  formatDeadline,
  calculateDeadline,
  buildManualRemediationLink,
  getManualRemediationLinkLabel,
  getWebUiUrl,
} from '../format-utils';
import { resetChannelLambdaEnvironmentCache } from '../channelLambdaEnvironment';
import { createEvent } from './test-factories';

describe('getWebUiUrl', () => {
  const originalWebUiUrl = process.env.WEB_UI_URL;

  afterEach(() => {
    process.env.WEB_UI_URL = originalWebUiUrl;
    resetChannelLambdaEnvironmentCache();
  });

  it('returns the configured URL when WEB_UI_URL is set', () => {
    process.env.WEB_UI_URL = 'https://ui.example.com';
    resetChannelLambdaEnvironmentCache();
    expect(getWebUiUrl()).toBe('https://ui.example.com');
  });

  it('returns an empty string when WEB_UI_URL is unset (Web UI not deployed)', () => {
    delete process.env.WEB_UI_URL;
    resetChannelLambdaEnvironmentCache();
    expect(getWebUiUrl()).toBe('');
  });
});

describe('formatSubject', () => {
  it('should format controlId, severity, eventType, and title', () => {
    const result = formatSubject(createEvent({ title: 'Root account access key exists' }), 255);
    expect(result).toBe('[ASR] CIS.1.1 High finding: Root account access key exists');
  });

  it('should truncate to the given max length', () => {
    const result = formatSubject(createEvent({ title: 'A'.repeat(200) }), 50);
    expect(result).toHaveLength(50);
  });

  it('should not truncate short subjects', () => {
    const result = formatSubject(createEvent({ title: 'Short' }), 255);
    expect(result).toBe('[ASR] CIS.1.1 High finding: Short');
    expect(result.length).toBeLessThanOrEqual(255);
  });
});

describe('formatEventDescription', () => {
  it('should include all required fields', () => {
    const result = formatEventDescription(createEvent(), 'My Config');
    expect(result).toContain('Configuration: My Config');
    expect(result).toContain('Severity: High');
    expect(result).toContain('Control: CIS.1.1');
    expect(result).toContain('Account: 123456789012');
    expect(result).toContain('Region: us-east-1');
    expect(result).toContain('Resource: AWS::IAM::User — test-user');
    expect(result).toContain('Detected: 2024-01-01T00:00:00Z');
  });

  it('should include optional description when present', () => {
    const result = formatEventDescription(createEvent({ description: 'Some details' }), 'Config');
    expect(result).toContain('Some details');
  });

  it('should include findingDescription on a labeled line when present', () => {
    const result = formatEventDescription(
      createEvent({ findingDescription: 'S3 bucket allows public access' }),
      'Config',
    );
    expect(result).toContain('Finding Description: S3 bucket allows public access');
  });

  it('should omit the Finding Description line when findingDescription is absent', () => {
    const result = formatEventDescription(createEvent(), 'Config');
    expect(result).not.toContain('Finding Description');
  });

  it('should include remediation fields when present', () => {
    const result = formatEventDescription(
      createEvent({ remediationStatus: 'COMPLETED', remediationMessage: 'Fixed it' }),
      'Config',
    );
    expect(result).toContain('Remediation Status: COMPLETED');
    expect(result).toContain('Remediation Message: Fixed it');
  });

  it('should omit remediation fields when absent', () => {
    const result = formatEventDescription(createEvent(), 'Config');
    expect(result).not.toContain('Remediation Status');
    expect(result).not.toContain('Remediation Message');
  });

  it('should apply custom line formatter', () => {
    const jiraLine = (label: string, value: string): string => `*${label}:* ${value}`;
    const result = formatEventDescription(createEvent(), 'Config', undefined, jiraLine);
    expect(result).toContain('*Configuration:* Config');
    expect(result).toContain('*Severity:* High');
  });

  it('should join lines with newlines and filter empty strings', () => {
    const result = formatEventDescription(createEvent(), 'Config');
    const lines = result.split('\n');
    expect(lines.every((line) => line.length > 0)).toBe(true);
  });

  it('should include remediation link (to Findings) for finding events', () => {
    const result = formatEventDescription(createEvent(), 'Config', {
      includeManualRemediationLink: true,
      includeRemediationDeadline: false,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    });
    expect(result).toContain('Remediation link');
    expect(result).toContain('/findings?findingId=');
  });

  it('should include history link (to Remediation History) for remediation events', () => {
    const result = formatEventDescription(createEvent({ eventType: 'remediation' }), 'Config', {
      includeManualRemediationLink: true,
      includeRemediationDeadline: false,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    });
    expect(result).toContain('History link');
    expect(result).toContain('/history?findingId=');
    expect(result).not.toContain('/findings?findingId=');
  });

  it('should include enable automation link when contentOptions flag is set', () => {
    const result = formatEventDescription(createEvent(), 'Config', {
      includeManualRemediationLink: false,
      includeRemediationDeadline: false,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: true,
    });
    expect(result).toContain('Control Settings');
    expect(result).toContain('/controls?controlId=');
  });

  it('should include remediation deadline when contentOptions flag and days are set', () => {
    const result = formatEventDescription(createEvent({ detectedAt: '2024-01-01T00:00:00Z' }), 'Config', {
      includeManualRemediationLink: false,
      includeRemediationDeadline: true,
      enforceDeadline: false,
      remediationDeadlineDays: 30,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    });
    expect(result).toContain('Remediation Deadline');
  });

  it('should omit remediation deadline when days are not set', () => {
    const result = formatEventDescription(createEvent(), 'Config', {
      includeManualRemediationLink: false,
      includeRemediationDeadline: true,
      enforceDeadline: false,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    });
    expect(result).not.toContain('Remediation Deadline');
  });

  it('should display notification type as first line, distinguishing findings from remediations', () => {
    // Arrange
    const findingEvent = createEvent({ eventType: 'finding' });
    const remediationEvent = createEvent({ eventType: 'remediation' });

    // Act
    const findingResult = formatEventDescription(findingEvent, 'Config');
    const remediationResult = formatEventDescription(remediationEvent, 'Config');

    // Assert — correct display labels
    expect(findingResult).toContain('Notification Type: New Finding');
    expect(remediationResult).toContain('Notification Type: Remediation Result');

    // Assert — notification type is the first line
    const findingLines = findingResult.split('\n');
    expect(findingLines[0]).toBe('Notification Type: New Finding');

    const remediationLines = remediationResult.split('\n');
    expect(remediationLines[0]).toBe('Notification Type: Remediation Result');
  });

  it('should include attribution line at the end for both finding and remediation event types', () => {
    // Arrange
    const findingEvent = createEvent({ eventType: 'finding' });
    const remediationEvent = createEvent({ eventType: 'remediation' });

    // Act
    const findingResult = formatEventDescription(findingEvent, 'Config');
    const remediationResult = formatEventDescription(remediationEvent, 'Config');

    // Assert — attribution is present
    expect(findingResult).toContain('Sent by Automated Security Response on AWS');
    expect(remediationResult).toContain('Sent by Automated Security Response on AWS');

    // Assert — attribution appears at the end (last line)
    const findingLines = findingResult.split('\n');
    expect(findingLines[findingLines.length - 1]).toBe('Sent by Automated Security Response on AWS');

    const remediationLines = remediationResult.split('\n');
    expect(remediationLines[remediationLines.length - 1]).toBe('Sent by Automated Security Response on AWS');
  });
});

describe('buildManualRemediationLink', () => {
  it('routes finding events to /findings and encodes the finding id', () => {
    const url = buildManualRemediationLink('evt/1?x=y', 'finding');
    expect(url).toContain('/findings?findingId=evt%2F1%3Fx%3Dy');
  });

  it('routes remediation events to /history', () => {
    const url = buildManualRemediationLink('evt-2', 'remediation');
    expect(url).toContain('/history?findingId=evt-2');
  });

  it('defaults to the Findings page when no event type is provided', () => {
    const url = buildManualRemediationLink('evt-3');
    expect(url).toContain('/findings?findingId=evt-3');
  });
});

describe('getManualRemediationLinkLabel', () => {
  it('returns "Remediation link" for finding events', () => {
    expect(getManualRemediationLinkLabel('finding')).toBe('Remediation link');
  });

  it('returns "History link" for remediation events', () => {
    expect(getManualRemediationLinkLabel('remediation')).toBe('History link');
  });
});

describe('calculateDeadline', () => {
  const fixedClock = { now: () => new Date('2024-01-15T00:00:00Z') };

  it('should calculate days remaining correctly', () => {
    const result = calculateDeadline('2024-01-01T00:00:00Z', 30, fixedClock);
    expect(result).toBeDefined();
    expect(result!.daysRemaining).toBe(16);
    expect(result!.deadlineDate).toBe('2024-01-31T00:00:00.000Z');
  });

  it('should return negative days when overdue', () => {
    const result = calculateDeadline('2024-01-01T00:00:00Z', 5, fixedClock);
    expect(result).toBeDefined();
    expect(result!.daysRemaining).toBeLessThan(0);
  });

  it('should return undefined for invalid date', () => {
    const result = calculateDeadline('invalid-date', 30, fixedClock);
    expect(result).toBeUndefined();
  });
});

describe('formatDeadline', () => {
  it('should format a future deadline with days remaining', () => {
    const clock = { now: () => new Date('2024-01-15T00:00:00Z') };
    const result = formatDeadline('2024-01-01T00:00:00Z', 30, clock);
    expect(result).toContain('day(s) remaining');
    expect(result).not.toContain('OVERDUE');
  });

  it('should format an overdue deadline', () => {
    const clock = { now: () => new Date('2024-02-15T00:00:00Z') };
    const result = formatDeadline('2024-01-01T00:00:00Z', 5, clock);
    expect(result).toContain('OVERDUE');
    expect(result).toMatch(/OVERDUE by \d+ day\(s\)/);
  });
});
