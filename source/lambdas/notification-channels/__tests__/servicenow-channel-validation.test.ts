// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  checkServiceNowInstanceUrl,
  checkServiceNowChannelFields,
  ServiceNowChannelConfigSchema,
  JiraChannelConfigSchema,
  NOTIFICATION_CHANNEL_SECRET_PREFIX,
  type ServiceNowChannelFieldInput,
} from '@asr/data-models';

describe('checkServiceNowInstanceUrl', () => {
  it('returns null for valid HTTPS URLs', () => {
    // ARRANGE
    const urls = ['https://company.service-now.com', 'https://custom.domain.com'];

    // ACT & ASSERT
    for (const url of urls) {
      expect(checkServiceNowInstanceUrl(url)).toBeNull();
    }
  });

  it('returns error when URL is empty', () => {
    // ARRANGE
    const url = '';

    // ACT
    const result = checkServiceNowInstanceUrl(url);

    // ASSERT
    expect(result).toBe('ServiceNow instance URL is required.');
  });

  it('returns error when URL is not HTTPS', () => {
    // ARRANGE
    const url = 'http://company.service-now.com';

    // ACT
    const result = checkServiceNowInstanceUrl(url);

    // ASSERT
    expect(result).toMatch(/HTTPS/);
  });

  it('returns error when URL exceeds 2,048 characters', () => {
    // ARRANGE
    const url = 'https://company.service-now.com/' + 'a'.repeat(2048);

    // ACT
    const result = checkServiceNowInstanceUrl(url);

    // ASSERT
    expect(result).toMatch(/2,048/);
  });

  it('returns error when URL has query parameters, fragments, or trailing slash', () => {
    // ARRANGE
    const queryParams = 'https://company.service-now.com?foo=bar';
    const fragment = 'https://company.service-now.com#section';
    const trailingSlash = 'https://company.service-now.com/';

    // ACT & ASSERT
    expect(checkServiceNowInstanceUrl(queryParams)).toMatch(/query parameters/);
    expect(checkServiceNowInstanceUrl(fragment)).toMatch(/fragment/);
    expect(checkServiceNowInstanceUrl(trailingSlash)).toMatch(/trailing slash/);
  });

  it('returns error when URL is not parseable', () => {
    // ARRANGE
    const url = 'not-a-valid-url';

    // ACT
    const result = checkServiceNowInstanceUrl(url);

    // ASSERT
    expect(result).toMatch(/not a valid URL/);
  });
});

describe('checkServiceNowChannelFields', () => {
  const validInput: ServiceNowChannelFieldInput = {
    endpointUrl: 'https://company.service-now.com',
    tableName: 'incident',
    credentialsSecretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}servicenow-creds`,
  };

  it('returns empty object for valid input', () => {
    // ARRANGE
    const input = { ...validInput };

    // ACT
    const errors = checkServiceNowChannelFields(input);

    // ASSERT
    expect(errors).toEqual({});
  });

  it('returns endpointUrl error for invalid URLs', () => {
    // ARRANGE
    const input: ServiceNowChannelFieldInput = { ...validInput, endpointUrl: 'http://insecure.com' };

    // ACT
    const errors = checkServiceNowChannelFields(input);

    // ASSERT
    expect(errors.endpointUrl).toBeDefined();
    expect(errors.tableName).toBeUndefined();
    expect(errors.credentialsSecretArn).toBeUndefined();
  });

  it('returns tableName error when empty', () => {
    // ARRANGE
    const input: ServiceNowChannelFieldInput = { ...validInput, tableName: '' };

    // ACT
    const errors = checkServiceNowChannelFields(input);

    // ASSERT
    expect(errors.tableName).toBeDefined();
    expect(errors.endpointUrl).toBeUndefined();
  });

  it('returns tableName error when not matching pattern (uppercase, starts with digit, special chars, exceeds 80 chars)', () => {
    // ARRANGE
    const uppercase: ServiceNowChannelFieldInput = { ...validInput, tableName: 'Incident' };
    const startsWithDigit: ServiceNowChannelFieldInput = { ...validInput, tableName: '1incident' };
    const specialChars: ServiceNowChannelFieldInput = { ...validInput, tableName: 'incident-table' };
    const exceeds80: ServiceNowChannelFieldInput = { ...validInput, tableName: 'a'.repeat(81) };

    // ACT & ASSERT
    expect(checkServiceNowChannelFields(uppercase).tableName).toBeDefined();
    expect(checkServiceNowChannelFields(startsWithDigit).tableName).toBeDefined();
    expect(checkServiceNowChannelFields(specialChars).tableName).toBeDefined();
    expect(checkServiceNowChannelFields(exceeds80).tableName).toBeDefined();
  });

  it('accepts valid table names', () => {
    // ARRANGE
    const validNames = ['incident', 'security_incident', 'sn_si_incident', 'a'];

    // ACT & ASSERT
    for (const name of validNames) {
      const errors = checkServiceNowChannelFields({ ...validInput, tableName: name });
      expect(errors.tableName).toBeUndefined();
    }
  });

  it('returns credentialsSecretArn error when empty or missing required prefix', () => {
    // ARRANGE
    const empty: ServiceNowChannelFieldInput = { ...validInput, credentialsSecretArn: '' };
    const wrongPrefix: ServiceNowChannelFieldInput = {
      ...validInput,
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:wrong-prefix-secret',
    };

    // ACT
    const emptyErrors = checkServiceNowChannelFields(empty);
    const wrongPrefixErrors = checkServiceNowChannelFields(wrongPrefix);

    // ASSERT
    expect(emptyErrors.credentialsSecretArn).toBeDefined();
    expect(wrongPrefixErrors.credentialsSecretArn).toContain(NOTIFICATION_CHANNEL_SECRET_PREFIX);
  });

  it('returns customFieldMappings error when key exceeds 64 chars or value exceeds 256 chars or more than 20 entries', () => {
    // ARRANGE
    const longKey: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: 'k'.repeat(65), value: 'valid' }],
    };
    const longValue: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: 'valid_key', value: 'v'.repeat(257) }],
    };
    const tooMany: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: Array.from({ length: 21 }, (_, i) => ({ key: `field_${i}`, value: `value_${i}` })),
    };

    // ACT & ASSERT
    expect(checkServiceNowChannelFields(longKey).customFieldMappings).toBe(
      'Custom field mapping [0]: key must not exceed 64 characters.',
    );
    expect(checkServiceNowChannelFields(longValue).customFieldMappings).toBe(
      'Custom field mapping [0]: value must not exceed 256 characters.',
    );
    expect(checkServiceNowChannelFields(tooMany).customFieldMappings).toBeDefined();
  });

  it('returns customFieldMappings error when key or value is empty or whitespace-only', () => {
    // ARRANGE
    const emptyKey: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: '   ', value: 'valid' }],
    };
    const emptyValue: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: 'valid_key', value: '  ' }],
    };

    // ACT & ASSERT
    expect(checkServiceNowChannelFields(emptyKey).customFieldMappings).toBe(
      'Custom field mapping [0]: key must not be empty.',
    );
    expect(checkServiceNowChannelFields(emptyValue).customFieldMappings).toBe(
      'Custom field mapping [0]: value must not be empty.',
    );
  });

  it('includes the index of the invalid mapping in the error message', () => {
    // ARRANGE
    const input: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: [
        { key: 'valid_key', value: 'valid_value' },
        { key: 'k'.repeat(65), value: 'valid' },
      ],
    };

    // ACT & ASSERT
    expect(checkServiceNowChannelFields(input).customFieldMappings).toBe(
      'Custom field mapping [1]: key must not exceed 64 characters.',
    );
  });

  it('returns customFieldMappings error when key conflicts with a reserved ServiceNow field', () => {
    // ARRANGE
    const input: ServiceNowChannelFieldInput = {
      ...validInput,
      customFieldMappings: [{ key: 'short_description', value: 'override attempt' }],
    };

    // ACT & ASSERT
    expect(checkServiceNowChannelFields(input).customFieldMappings).toBe(
      'Custom field mapping [0]: key "short_description" conflicts with a reserved ServiceNow record field.',
    );
  });

  it('returns multiple field errors simultaneously', () => {
    // ARRANGE
    const input: ServiceNowChannelFieldInput = {
      endpointUrl: 'http://insecure.com',
      tableName: 'INVALID',
      credentialsSecretArn: '',
      customFieldMappings: [{ key: 'k'.repeat(65), value: 'valid' }],
    };

    // ACT
    const errors = checkServiceNowChannelFields(input);

    // ASSERT
    expect(errors.endpointUrl).toBeDefined();
    expect(errors.tableName).toBeDefined();
    expect(errors.credentialsSecretArn).toBeDefined();
    expect(errors.customFieldMappings).toBeDefined();
  });
});

describe('ServiceNowChannelConfigSchema', () => {
  it('rejects custom field key exceeding 64 chars', () => {
    // ARRANGE
    const config = {
      type: 'servicenow' as const,
      enabled: true,
      endpointUrl: 'https://company.service-now.com',
      tableName: 'incident',
      credentialsSecretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}sn-creds`,
      customFieldMappings: [{ key: 'k'.repeat(65), value: 'valid' }],
    };

    // ACT
    const result = ServiceNowChannelConfigSchema.safeParse(config);

    // ASSERT
    expect(result.success).toBe(false);
  });

  it('rejects custom field value exceeding 256 chars', () => {
    // ARRANGE
    const config = {
      type: 'servicenow' as const,
      enabled: true,
      endpointUrl: 'https://company.service-now.com',
      tableName: 'incident',
      credentialsSecretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}sn-creds`,
      customFieldMappings: [{ key: 'valid_key', value: 'v'.repeat(257) }],
    };

    // ACT
    const result = ServiceNowChannelConfigSchema.safeParse(config);

    // ASSERT
    expect(result.success).toBe(false);
  });
});

describe('JiraChannelConfigSchema', () => {
  it('still accepts custom field key up to 80 chars and value up to 1024 chars', () => {
    // ARRANGE
    const config = {
      type: 'jira' as const,
      enabled: true,
      projectKey: 'SEC',
      issueType: 'Bug',
      endpointUrl: 'https://company.atlassian.net',
      credentialsSecretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}jira-creds`,
      customFieldMappings: [{ key: 'k'.repeat(80), value: 'v'.repeat(1024) }],
    };

    // ACT
    const result = JiraChannelConfigSchema.safeParse(config);

    // ASSERT
    expect(result.success).toBe(true);
  });
});
