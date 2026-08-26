// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import { DeliveryChannelConfig } from '@asr/data-models';
import { ChannelChecker } from '../../services/channelChecker';

const secretsMock = mockClient(SecretsManagerClient);
const logger = new Logger({ logLevel: 'SILENT' });
const secretsClient = new SecretsManagerClient({});

describe('ChannelChecker', () => {
  let checker: ChannelChecker;

  beforeEach(() => {
    secretsMock.reset();
    checker = new ChannelChecker(logger, secretsClient);
  });

  describe('ARN format validation', () => {
    it('should pass validation for a valid Secrets Manager ARN', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'slack',
        enabled: true,
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-abc123',
      };
      secretsMock.on(GetSecretValueCommand).resolves({ SecretString: '{"token":"xoxb-test"}' });

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(true);
      expect(results[0].channelType).toBe('slack');
      expect(results[0].error).toBeUndefined();
    });

    it('should fail validation with descriptive error for an invalid ARN syntax', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'slack',
        enabled: true,
        credentialsSecretArn: 'not-a-valid-arn',
      };

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('slack');
      expect(results[0].error).toMatch(/invalid.*arn/i);
    });
  });

  describe('URL format validation', () => {
    it('should pass validation for a valid HTTPS endpoint URL', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'jira',
        enabled: true,
        projectKey: 'SEC',
        issueType: 'Bug',
        endpointUrl: 'https://jira.example.com/rest/api/2',
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-abc123',
      };
      secretsMock.on(GetSecretValueCommand).resolves({ SecretString: '{"user":"admin","token":"secret"}' });

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(true);
      expect(results[0].channelType).toBe('jira');
    });

    it('should fail validation with descriptive error for a non-HTTPS URL', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'servicenow',
        enabled: true,
        endpointUrl: 'http://servicenow.example.com/api/now/table/incident',
        tableName: 'incident',
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/snow-abc123',
      };

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('servicenow');
      expect(results[0].error).toMatch(/https/i);
    });
  });

  describe('secret retrieval validation', () => {
    it('should fail validation when secret retrieval throws an error', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'slack',
        enabled: true,
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/slack-abc123',
      };
      secretsMock.on(GetSecretValueCommand).rejects(new Error('Secrets Manager access denied'));

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('slack');
      expect(results[0].error).toMatch(/secret|credential/i);
    });
  });

  describe('timeout enforcement', () => {
    afterEach(() => {
      jest.useRealTimers();
    });

    it('should fail validation with timeout error when secret retrieval exceeds 10 seconds', async () => {
      // ARRANGE
      jest.useFakeTimers();
      const channel: DeliveryChannelConfig = {
        type: 'jira',
        enabled: true,
        projectKey: 'SEC',
        issueType: 'Bug',
        endpointUrl: 'https://jira.example.com/rest/api/2',
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-abc123',
      };
      secretsMock.on(GetSecretValueCommand).callsFake(() => new Promise(() => {}));

      // ACT
      const resultPromise = checker.checkChannels([channel]);
      jest.advanceTimersByTime(10_000);
      const results = await resultPromise;

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('jira');
      expect(results[0].error).toMatch(/timeout|timed out/i);
    });
  });

  describe('independent channel validation', () => {
    it('should continue validating remaining channels after one fails', async () => {
      // ARRANGE
      const channels: DeliveryChannelConfig[] = [
        {
          type: 'slack',
          enabled: true,
          credentialsSecretArn: 'not-a-valid-arn',
        },
        {
          type: 'sns',
          enabled: true,
          topicArn: 'arn:aws:sns:us-east-1:123456789012:valid-topic',
        },
        {
          type: 'jira',
          enabled: true,
          projectKey: 'SEC',
          issueType: 'Bug',
          endpointUrl: 'https://jira.example.com',
          credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:asr/notifications/jira-abc123',
        },
      ];
      secretsMock.on(GetSecretValueCommand).resolves({ SecretString: '{"user":"admin","token":"secret"}' });

      // ACT
      const results = await checker.checkChannels(channels);

      // ASSERT
      expect(results).toHaveLength(3);
      expect(results[0].channelType).toBe('slack');
      expect(results[0].isValid).toBe(false);
      expect(results[1].channelType).toBe('sns');
      expect(results[1].isValid).toBe(true);
      expect(results[2].channelType).toBe('jira');
      expect(results[2].isValid).toBe(true);
    });
  });

  describe('SNS topic ARN validation', () => {
    it('should pass validation for a valid SNS topic ARN', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'sns',
        enabled: true,
        topicArn: 'arn:aws:sns:us-east-1:123456789012:my-notifications-topic',
      };

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(true);
      expect(results[0].channelType).toBe('sns');
    });

    it('should fail validation for an invalid SNS topic ARN', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'sns',
        enabled: true,
        topicArn: 'arn:aws:sqs:us-east-1:123456789012:not-an-sns-topic',
      };

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('sns');
      expect(results[0].error).toMatch(/arn|format|sns/i);
    });
  });

  describe('credential format edge cases', () => {
    it('should reject empty string for both ARN and URL validation', async () => {
      // ARRANGE
      const channels: DeliveryChannelConfig[] = [
        {
          type: 'slack',
          enabled: true,
          credentialsSecretArn: '',
        },
        {
          type: 'jira',
          enabled: true,
          projectKey: 'SEC',
          issueType: 'Bug',
          endpointUrl: '',
          credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:valid-abc123',
        },
      ];

      // ACT
      const results = await checker.checkChannels(channels);

      // ASSERT
      expect(results).toHaveLength(2);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('slack');
      expect(results[0].error).toBeDefined();
      expect(results[1].isValid).toBe(false);
      expect(results[1].channelType).toBe('jira');
      expect(results[1].error).toBeDefined();
    });

    it.each([
      ['missing region/account/resource', 'arn:aws:secretsmanager'],
      ['missing account/resource', 'arn:aws:secretsmanager:us-east-1'],
      ['missing resource', 'arn:aws:secretsmanager:us-east-1:123456789012'],
      ['empty resource name', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:'],
      ['non-numeric account', 'arn:aws:secretsmanager:us-east-1:not-a-number:secret:my-secret'],
    ])('should reject ARN with %s', async (_desc, arn) => {
      // ARRANGE
      const channel: DeliveryChannelConfig = { type: 'slack', enabled: true, credentialsSecretArn: arn };

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results[0].isValid).toBe(false);
      expect(results[0].error).toMatch(/invalid.*arn/i);
    });

    it('should reject URL with no host', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'servicenow',
        enabled: true,
        endpointUrl: 'https://',
        tableName: 'incident',
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:snow-abc123',
      };

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(false);
      expect(results[0].channelType).toBe('servicenow');
      expect(results[0].error).toMatch(/url/i);
      expect(secretsMock.commandCalls(GetSecretValueCommand)).toHaveLength(0);
    });

    it('should pass HTTPS URL with query parameters and fragments', async () => {
      // ARRANGE
      const channel: DeliveryChannelConfig = {
        type: 'jira',
        enabled: true,
        projectKey: 'SEC',
        issueType: 'Bug',
        endpointUrl: 'https://jira.example.com/rest/api/2?timeout=30#section',
        credentialsSecretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:jira-abc123',
      };
      secretsMock.on(GetSecretValueCommand).resolves({ SecretString: '{"user":"admin","token":"secret"}' });

      // ACT
      const results = await checker.checkChannels([channel]);

      // ASSERT
      expect(results).toHaveLength(1);
      expect(results[0].isValid).toBe(true);
      expect(results[0].channelType).toBe('jira');
    });

    it('should pass SNS topic ARN with valid format across partitions', async () => {
      // ARRANGE
      const channels: DeliveryChannelConfig[] = [
        {
          type: 'sns',
          enabled: true,
          topicArn: 'arn:aws:sns:us-west-2:987654321098:security-alerts',
        },
        {
          type: 'sns',
          enabled: true,
          topicArn: 'arn:aws-cn:sns:cn-north-1:123456789012:china-topic',
        },
        {
          type: 'sns',
          enabled: true,
          topicArn: 'arn:aws-us-gov:sns:us-gov-west-1:123456789012:gov-topic',
        },
      ];

      // ACT
      const results = await checker.checkChannels(channels);

      // ASSERT
      expect(results).toHaveLength(3);
      for (const result of results) {
        expect(result.isValid).toBe(true);
        expect(result.channelType).toBe('sns');
      }
    });
  });
});
