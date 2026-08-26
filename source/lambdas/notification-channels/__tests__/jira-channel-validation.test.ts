// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  checkJiraChannelFields,
  JIRA_PROJECT_KEY_PATTERN,
  JIRA_CUSTOM_FIELD_KEY_PATTERN,
  NOTIFICATION_CHANNEL_SECRET_PREFIX,
  type JiraChannelFieldInput,
} from '@asr/data-models';

describe('checkJiraChannelFields', () => {
  const validInput: JiraChannelFieldInput = {
    endpointUrl: 'https://company.atlassian.net',
    projectKey: 'SEC',
    issueType: 'Bug',
    credentialsSecretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}jira-creds`,
  };

  it('returns empty object for valid input', () => {
    // ARRANGE
    const input = { ...validInput };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors).toEqual({});
  });

  it('returns endpointUrl error when URL is empty', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = { ...validInput, endpointUrl: '' };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.endpointUrl).toBeDefined();
    expect(errors.projectKey).toBeUndefined();
    expect(errors.issueType).toBeUndefined();
    expect(errors.credentialsSecretArn).toBeUndefined();
  });

  it('returns endpointUrl error when URL is not HTTPS', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = { ...validInput, endpointUrl: 'http://jira.example.com' };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.endpointUrl).toContain('HTTPS');
  });

  it('returns endpointUrl error when URL has trailing slash, query params, or fragment', () => {
    // ARRANGE
    const trailingSlash: JiraChannelFieldInput = { ...validInput, endpointUrl: 'https://jira.example.com/' };
    const queryParams: JiraChannelFieldInput = { ...validInput, endpointUrl: 'https://jira.example.com?foo=bar' };
    const fragment: JiraChannelFieldInput = { ...validInput, endpointUrl: 'https://jira.example.com#section' };

    // ACT
    const trailingSlashErrors = checkJiraChannelFields(trailingSlash);
    const queryParamsErrors = checkJiraChannelFields(queryParams);
    const fragmentErrors = checkJiraChannelFields(fragment);

    // ASSERT
    expect(trailingSlashErrors.endpointUrl).toBeDefined();
    expect(queryParamsErrors.endpointUrl).toBeDefined();
    expect(fragmentErrors.endpointUrl).toBeDefined();
  });

  it('returns endpointUrl error when URL exceeds 2,048 characters', () => {
    // ARRANGE
    const longUrl = `https://${'a'.repeat(2048)}.example.com`;
    const input: JiraChannelFieldInput = { ...validInput, endpointUrl: longUrl };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.endpointUrl).toBeDefined();
  });

  it('returns projectKey error when key is empty', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = { ...validInput, projectKey: '' };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.projectKey).toBeDefined();
    expect(errors.endpointUrl).toBeUndefined();
  });

  it('returns projectKey error when key does not match the required pattern', () => {
    // ARRANGE
    const lowercase: JiraChannelFieldInput = { ...validInput, projectKey: 'sec' };
    const tooShort: JiraChannelFieldInput = { ...validInput, projectKey: 'A' };
    const tooLong: JiraChannelFieldInput = { ...validInput, projectKey: 'ABCDEFGHIJK' };
    const invalidChars: JiraChannelFieldInput = { ...validInput, projectKey: 'SEC-1' };
    const startsWithDigit: JiraChannelFieldInput = { ...validInput, projectKey: '1SEC' };

    // ACT & ASSERT
    expect(checkJiraChannelFields(lowercase).projectKey).toBeDefined();
    expect(checkJiraChannelFields(tooShort).projectKey).toBeDefined();
    expect(checkJiraChannelFields(tooLong).projectKey).toBeDefined();
    expect(checkJiraChannelFields(invalidChars).projectKey).toBeDefined();
    expect(checkJiraChannelFields(startsWithDigit).projectKey).toBeDefined();
  });

  it('accepts valid project keys', () => {
    // ARRANGE
    const keys = ['SE', 'SEC', 'OPS_1', 'ABCDEFGHIJ', 'A1'];

    // ACT & ASSERT
    for (const key of keys) {
      const errors = checkJiraChannelFields({ ...validInput, projectKey: key });
      expect(errors.projectKey).toBeUndefined();
    }
  });

  it('returns issueType error when empty or whitespace-only', () => {
    // ARRANGE
    const empty: JiraChannelFieldInput = { ...validInput, issueType: '' };
    const whitespace: JiraChannelFieldInput = { ...validInput, issueType: '   ' };

    // ACT
    const emptyErrors = checkJiraChannelFields(empty);
    const whitespaceErrors = checkJiraChannelFields(whitespace);

    // ASSERT
    expect(emptyErrors.issueType).toBeDefined();
    expect(whitespaceErrors.issueType).toBeDefined();
  });

  it('returns credentialsSecretArn error when empty', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = { ...validInput, credentialsSecretArn: '' };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.credentialsSecretArn).toBeDefined();
  });

  it('returns credentialsSecretArn error when missing the required prefix', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = {
      ...validInput,
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:wrong-prefix-secret',
    };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.credentialsSecretArn).toContain(NOTIFICATION_CHANNEL_SECRET_PREFIX);
  });

  it('returns customFieldMappings error when key does not match customfield_<number> pattern', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: 'project', value: 'overwrite attempt' }],
    };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.customFieldMappings).toContain('customfield_');
  });

  it('returns customFieldMappings error when key exceeds 80 characters', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: `customfield_${'1'.repeat(70)}`, value: 'valid' }],
    };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.customFieldMappings).toBeDefined();
  });

  it('returns customFieldMappings error when value exceeds 1024 characters', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: 'customfield_10001', value: 'v'.repeat(1025) }],
    };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.customFieldMappings).toBeDefined();
  });

  it('returns customFieldMappings error when exceeding 20 entries', () => {
    // ARRANGE
    const mappings = Array.from({ length: 21 }, (_, i) => ({ key: `customfield_${10000 + i}`, value: `value_${i}` }));
    const input: JiraChannelFieldInput = { ...validInput, customFieldMappings: mappings };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.customFieldMappings).toBeDefined();
  });

  it('returns multiple field errors simultaneously when multiple fields are invalid', () => {
    // ARRANGE
    const input: JiraChannelFieldInput = {
      endpointUrl: 'http://insecure.com',
      projectKey: 'bad',
      issueType: '',
      credentialsSecretArn: '',
    };

    // ACT
    const errors = checkJiraChannelFields(input);

    // ASSERT
    expect(errors.endpointUrl).toBeDefined();
    expect(errors.projectKey).toBeDefined();
    expect(errors.issueType).toBeDefined();
    expect(errors.credentialsSecretArn).toBeDefined();
  });

  it('exports JIRA_PROJECT_KEY_PATTERN regex constant', () => {
    // ASSERT
    expect(JIRA_PROJECT_KEY_PATTERN).toBeInstanceOf(RegExp);
    expect(JIRA_PROJECT_KEY_PATTERN.test('SEC')).toBe(true);
    expect(JIRA_PROJECT_KEY_PATTERN.test('sec')).toBe(false);
  });

  it('exports JIRA_CUSTOM_FIELD_KEY_PATTERN that only allows customfield_<number>', () => {
    // ASSERT
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN).toBeInstanceOf(RegExp);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('customfield_10001')).toBe(true);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('customfield_0')).toBe(true);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('project')).toBe(false);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('summary')).toBe(false);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('issuetype')).toBe(false);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('customfield_abc')).toBe(false);
    expect(JIRA_CUSTOM_FIELD_KEY_PATTERN.test('customfield_')).toBe(false);
  });
});
