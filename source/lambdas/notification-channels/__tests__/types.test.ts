// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  SEVERITY_MAP,
  SeverityLevel,
  isSeverityLevel,
  getChannelSeverity,
  OCSF_SEVERITY_MAP,
  OcsfSeverityId,
  ChannelType,
  JIRA_CREATE_ISSUE_PATH,
  parseJiraCredentials,
  parseServiceNowCredentials,
  isJiraCreateIssueResponse,
  isServiceNowCreateResponse,
  isChannelFanoutMessage,
} from '../types';
import { CredentialParsingError } from '../notification-channel-errors';

describe('SEVERITY_MAP', () => {
  const expectedLevels: SeverityLevel[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

  it('should contain all severity levels', () => {
    expect(Object.keys(SEVERITY_MAP)).toEqual(expectedLevels);
  });

  it('should have urgency values between 1 and 4', () => {
    for (const level of expectedLevels) {
      expect(SEVERITY_MAP[level].urgency).toBeGreaterThanOrEqual(1);
      expect(SEVERITY_MAP[level].urgency).toBeLessThanOrEqual(4);
    }
  });

  it('should have urgency in descending severity order', () => {
    expect(SEVERITY_MAP.Critical.urgency).toBeLessThan(SEVERITY_MAP.High.urgency);
    expect(SEVERITY_MAP.High.urgency).toBeLessThan(SEVERITY_MAP.Medium.urgency);
    expect(SEVERITY_MAP.Medium.urgency).toBeLessThan(SEVERITY_MAP.Low.urgency);
  });

  it('should have jiraPriority for every level', () => {
    for (const level of expectedLevels) {
      expect(SEVERITY_MAP[level].jiraPriority).toBeDefined();
      expect(SEVERITY_MAP[level].jiraPriority.length).toBeGreaterThan(0);
    }
  });
});

describe('isSeverityLevel', () => {
  it('should return true for valid severity levels', () => {
    expect(isSeverityLevel('Critical')).toBe(true);
    expect(isSeverityLevel('High')).toBe(true);
    expect(isSeverityLevel('Medium')).toBe(true);
    expect(isSeverityLevel('Low')).toBe(true);
    expect(isSeverityLevel('Informational')).toBe(true);
  });

  it('should return false for invalid severity levels', () => {
    expect(isSeverityLevel('critical')).toBe(false);
    expect(isSeverityLevel('CRITICAL')).toBe(false);
    expect(isSeverityLevel('Unknown')).toBe(false);
    expect(isSeverityLevel('')).toBe(false);
  });
});

describe('getChannelSeverity', () => {
  it('should return correct meta for title-case severity levels', () => {
    expect(getChannelSeverity('Critical')).toEqual({ urgency: 1, jiraPriority: 'Highest' });
    expect(getChannelSeverity('High')).toEqual({ urgency: 2, jiraPriority: 'High' });
    expect(getChannelSeverity('Medium')).toEqual({ urgency: 3, jiraPriority: 'Medium' });
    expect(getChannelSeverity('Low')).toEqual({ urgency: 4, jiraPriority: 'Low' });
    expect(getChannelSeverity('Informational')).toEqual({ urgency: 4, jiraPriority: 'Lowest' });
  });

  it('should return correct meta for uppercase ASFF severity labels', () => {
    expect(getChannelSeverity('CRITICAL')).toEqual({ urgency: 1, jiraPriority: 'Highest' });
    expect(getChannelSeverity('HIGH')).toEqual({ urgency: 2, jiraPriority: 'High' });
    expect(getChannelSeverity('MEDIUM')).toEqual({ urgency: 3, jiraPriority: 'Medium' });
    expect(getChannelSeverity('LOW')).toEqual({ urgency: 4, jiraPriority: 'Low' });
    expect(getChannelSeverity('INFORMATIONAL')).toEqual({ urgency: 4, jiraPriority: 'Lowest' });
  });

  it('should return correct meta for lowercase severity levels', () => {
    expect(getChannelSeverity('critical')).toEqual({ urgency: 1, jiraPriority: 'Highest' });
    expect(getChannelSeverity('low')).toEqual({ urgency: 4, jiraPriority: 'Low' });
  });

  it('should return undefined for unknown severity values', () => {
    expect(getChannelSeverity('Unknown')).toBeUndefined();
    expect(getChannelSeverity('')).toBeUndefined();
    expect(getChannelSeverity('Urgent')).toBeUndefined();
  });
});

describe('parseJiraCredentials', () => {
  it('should parse valid credentials with apiToken', () => {
    const result = parseJiraCredentials({ username: 'user', apiToken: 'token123' });
    expect(result).toEqual({ username: 'user', apiToken: 'token123' });
  });

  it('should accept password as fallback for apiToken', () => {
    const result = parseJiraCredentials({ username: 'user', password: 'pass123' });
    expect(result).toEqual({ username: 'user', apiToken: 'pass123' });
  });

  it('should resolve keys case-insensitively', () => {
    expect(parseJiraCredentials({ Username: 'user', ApiToken: 'tok' })).toEqual({ username: 'user', apiToken: 'tok' });
    expect(parseJiraCredentials({ USERNAME: 'user', APITOKEN: 'tok' })).toEqual({ username: 'user', apiToken: 'tok' });
    expect(parseJiraCredentials({ UserName: 'user', Password: 'p' })).toEqual({ username: 'user', apiToken: 'p' });
  });

  it('should throw CredentialParsingError when ambiguous case-variant keys exist', () => {
    expect(() => parseJiraCredentials({ username: 'user1', Username: 'user2', apiToken: 'tok' })).toThrow(
      CredentialParsingError,
    );
    expect(() => parseJiraCredentials({ username: 'user1', Username: 'user2', apiToken: 'tok' })).toThrow(
      'Ambiguous credential field: multiple case variants found for "username"',
    );
  });

  it('should throw CredentialParsingError for missing username', () => {
    expect(() => parseJiraCredentials({ apiToken: 'token' })).toThrow(CredentialParsingError);
    expect(() => parseJiraCredentials({ apiToken: 'token' })).toThrow('missing username');
  });

  it('should throw CredentialParsingError for missing apiToken and password', () => {
    expect(() => parseJiraCredentials({ username: 'user' })).toThrow(CredentialParsingError);
    expect(() => parseJiraCredentials({ username: 'user' })).toThrow('missing apiToken or password');
  });

  it('should throw CredentialParsingError for non-object input', () => {
    expect(() => parseJiraCredentials(null)).toThrow(CredentialParsingError);
    expect(() => parseJiraCredentials('string')).toThrow(CredentialParsingError);
  });
});

describe('parseServiceNowCredentials', () => {
  it('should parse valid credentials', () => {
    const result = parseServiceNowCredentials({ username: 'user', password: 'pass' });
    expect(result).toEqual({ username: 'user', password: 'pass' });
  });

  it('should resolve keys case-insensitively', () => {
    expect(parseServiceNowCredentials({ Username: 'user', Password: 'pass' })).toEqual({
      username: 'user',
      password: 'pass',
    });
    expect(parseServiceNowCredentials({ USERNAME: 'u', PASSWORD: 'p' })).toEqual({ username: 'u', password: 'p' });
  });

  it('should throw CredentialParsingError when ambiguous case-variant keys exist', () => {
    expect(() => parseServiceNowCredentials({ username: 'u1', Username: 'u2', password: 'p' })).toThrow(
      CredentialParsingError,
    );
    expect(() => parseServiceNowCredentials({ username: 'u1', Username: 'u2', password: 'p' })).toThrow(
      'Ambiguous credential field: multiple case variants found for "username"',
    );
  });

  it('should throw CredentialParsingError for missing username', () => {
    expect(() => parseServiceNowCredentials({ password: 'pass' })).toThrow(CredentialParsingError);
    expect(() => parseServiceNowCredentials({ password: 'pass' })).toThrow('missing username');
  });

  it('should throw CredentialParsingError for missing password', () => {
    expect(() => parseServiceNowCredentials({ username: 'user' })).toThrow(CredentialParsingError);
    expect(() => parseServiceNowCredentials({ username: 'user' })).toThrow('missing password');
  });

  it('should throw CredentialParsingError for non-object input', () => {
    expect(() => parseServiceNowCredentials(null)).toThrow(CredentialParsingError);
  });
});

describe('isJiraCreateIssueResponse', () => {
  it('should return true for valid response', () => {
    expect(isJiraCreateIssueResponse({ key: 'PROJ-123', id: '1', self: 'url' })).toBe(true);
  });

  it('should return false for missing key', () => {
    expect(isJiraCreateIssueResponse({ id: '1' })).toBe(false);
  });

  it('should return false for non-string key', () => {
    expect(isJiraCreateIssueResponse({ key: 123 })).toBe(false);
  });

  it('should return false for non-object', () => {
    expect(isJiraCreateIssueResponse(null)).toBe(false);
    expect(isJiraCreateIssueResponse('string')).toBe(false);
  });
});

describe('isServiceNowCreateResponse', () => {
  it('should return true for valid response with result', () => {
    expect(isServiceNowCreateResponse({ result: { sys_id: '123', number: 'INC001' } })).toBe(true);
  });

  it('should return true for response without result field', () => {
    expect(isServiceNowCreateResponse({})).toBe(true);
  });

  it('should return false for non-object', () => {
    expect(isServiceNowCreateResponse(null)).toBe(false);
    expect(isServiceNowCreateResponse('string')).toBe(false);
  });
});

describe('isChannelFanoutMessage', () => {
  it('should return true for a valid message shape', () => {
    expect(
      isChannelFanoutMessage({
        configId: 'config-1',
        configName: 'Test',
        contentOptions: {},
        channel: { type: 'email' },
        event: { eventId: 'e1' },
      }),
    ).toBe(true);
  });

  it('should return false for null', () => {
    expect(isChannelFanoutMessage(null)).toBe(false);
  });

  it('should return false for non-object', () => {
    expect(isChannelFanoutMessage('string')).toBe(false);
  });

  it('should return false when configId is missing', () => {
    expect(
      isChannelFanoutMessage({
        configName: 'Test',
        contentOptions: {},
        channel: { type: 'email' },
        event: { eventId: 'e1' },
      }),
    ).toBe(false);
  });

  it('should return false when channel is not an object', () => {
    expect(
      isChannelFanoutMessage({
        configId: 'config-1',
        configName: 'Test',
        contentOptions: {},
        channel: 'email',
        event: { eventId: 'e1' },
      }),
    ).toBe(false);
  });
});

describe('OCSF_SEVERITY_MAP', () => {
  it('should map all OCSF severity_id values (0–5) to valid SeverityLevels', () => {
    const ids: OcsfSeverityId[] = [0, 1, 2, 3, 4, 5];
    for (const id of ids) {
      expect(isSeverityLevel(OCSF_SEVERITY_MAP[id])).toBe(true);
    }
  });

  it('should map Critical (5) and High (4) correctly', () => {
    expect(OCSF_SEVERITY_MAP[5]).toBe('Critical');
    expect(OCSF_SEVERITY_MAP[4]).toBe('High');
  });

  it('should map lower severities correctly', () => {
    expect(OCSF_SEVERITY_MAP[3]).toBe('Medium');
    expect(OCSF_SEVERITY_MAP[2]).toBe('Low');
    expect(OCSF_SEVERITY_MAP[1]).toBe('Informational');
    expect(OCSF_SEVERITY_MAP[0]).toBe('Informational');
  });
});

describe('ChannelType', () => {
  it('should have all expected channel types', () => {
    expect(ChannelType.Email).toBe('email');
    expect(ChannelType.Slack).toBe('slack');
    expect(ChannelType.Jira).toBe('jira');
    expect(ChannelType.ServiceNow).toBe('servicenow');
    expect(ChannelType.Sns).toBe('sns');
  });

  it('should have exactly 5 members', () => {
    const values = Object.values(ChannelType);
    expect(values).toHaveLength(5);
  });
});

describe('JIRA_CREATE_ISSUE_PATH', () => {
  it('should be the JIRA v2 create issue endpoint', () => {
    expect(JIRA_CREATE_ISSUE_PATH).toBe('/rest/api/2/issue');
  });
});
