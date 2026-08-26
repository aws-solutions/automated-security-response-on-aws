// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  notificationChannelSecretArnSchema,
  checkSlackChannelFields,
  NOTIFICATION_CHANNEL_SECRET_PREFIX,
} from '@asr/data-models';

describe('notificationChannelSecretArnSchema', () => {
  const validPrefix = NOTIFICATION_CHANNEL_SECRET_PREFIX;

  it('accepts a valid Secrets Manager ARN with the required prefix', () => {
    // ARRANGE
    const arn = `arn:aws:secretsmanager:us-east-1:123456789012:secret:${validPrefix}slack-webhook`;

    // ACT
    const result = notificationChannelSecretArnSchema.safeParse(arn);

    // ASSERT
    expect(result.success).toBe(true);
  });

  it('accepts ARNs in aws-cn partition', () => {
    // ARRANGE
    const arn = `arn:aws-cn:secretsmanager:cn-north-1:123456789012:secret:${validPrefix}my-secret`;

    // ACT
    const result = notificationChannelSecretArnSchema.safeParse(arn);

    // ASSERT
    expect(result.success).toBe(true);
  });

  it('accepts ARNs in aws-us-gov partition', () => {
    // ARRANGE
    const arn = `arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:${validPrefix}gov-secret`;

    // ACT
    const result = notificationChannelSecretArnSchema.safeParse(arn);

    // ASSERT
    expect(result.success).toBe(true);
  });

  it('rejects an ARN without the required secret name prefix', () => {
    // ARRANGE
    const arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:some-other-secret';

    // ACT
    const result = notificationChannelSecretArnSchema.safeParse(arn);

    // ASSERT
    expect(result.success).toBe(false);
  });

  it('rejects an ARN with an invalid account ID (not 12 digits)', () => {
    // ARRANGE
    const arn = `arn:aws:secretsmanager:us-east-1:12345:secret:${validPrefix}slack`;

    // ACT
    const result = notificationChannelSecretArnSchema.safeParse(arn);

    // ASSERT
    expect(result.success).toBe(false);
  });

  it('rejects a non-secretsmanager ARN', () => {
    // ARRANGE
    const arn = `arn:aws:s3:::${validPrefix}bucket`;

    // ACT
    const result = notificationChannelSecretArnSchema.safeParse(arn);

    // ASSERT
    expect(result.success).toBe(false);
  });

  it('rejects an empty string', () => {
    // ARRANGE / ACT
    const result = notificationChannelSecretArnSchema.safeParse('');

    // ASSERT
    expect(result.success).toBe(false);
  });

  it('rejects a non-string value', () => {
    // ARRANGE / ACT
    const result = notificationChannelSecretArnSchema.safeParse(123);

    // ASSERT
    expect(result.success).toBe(false);
  });
});

describe('checkSlackChannelFields', () => {
  const validArn = `arn:aws:secretsmanager:us-east-1:123456789012:secret:${NOTIFICATION_CHANNEL_SECRET_PREFIX}slack-webhook`;
  const validChannelId = 'C0123456789';

  it('returns no errors for valid inputs', () => {
    // ARRANGE
    const input = { credentialsSecretArn: validArn, channelId: validChannelId };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors).toEqual({});
  });

  it('returns an error when credentialsSecretArn is empty', () => {
    // ARRANGE
    const input = { credentialsSecretArn: '  ', channelId: validChannelId };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors.credentialsSecretArn).toBeDefined();
    expect(errors.channelId).toBeUndefined();
  });

  it('returns an error when credentialsSecretArn does not have the required prefix', () => {
    // ARRANGE
    const input = {
      credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:wrong-prefix-secret',
      channelId: validChannelId,
    };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors.credentialsSecretArn).toContain(NOTIFICATION_CHANNEL_SECRET_PREFIX);
  });

  it('returns an error when channelId is empty', () => {
    // ARRANGE
    const input = { credentialsSecretArn: validArn, channelId: '' };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors.channelId).toBeDefined();
    expect(errors.credentialsSecretArn).toBeUndefined();
  });

  it('returns an error when channelId does not match the expected pattern', () => {
    // ARRANGE
    const input = { credentialsSecretArn: validArn, channelId: 'invalid-channel' };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors.channelId).toContain('Channel ID');
  });

  it('returns errors for both fields when both are invalid', () => {
    // ARRANGE
    const input = { credentialsSecretArn: '', channelId: '' };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors.credentialsSecretArn).toBeDefined();
    expect(errors.channelId).toBeDefined();
  });

  it('trims whitespace from inputs before validation', () => {
    // ARRANGE
    const input = { credentialsSecretArn: `  ${validArn}  `, channelId: `  ${validChannelId}  ` };

    // ACT
    const errors = checkSlackChannelFields(input);

    // ASSERT
    expect(errors).toEqual({});
  });
});
