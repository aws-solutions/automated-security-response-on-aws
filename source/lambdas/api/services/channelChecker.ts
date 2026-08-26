// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import {
  DeliveryChannelConfig,
  DeliveryChannelType,
  parseSnsTopicArn,
  secretsManagerArnSchema,
} from '@asr/data-models';

const VALIDATION_TIMEOUT_MS = 10_000;

export interface ChannelValidationResult {
  channelType: DeliveryChannelType;
  isValid: boolean;
  error?: string;
}

export class ChannelChecker {
  constructor(
    private readonly logger: Logger,
    private readonly secretsClient: SecretsManagerClient = new SecretsManagerClient({}),
  ) {}

  async checkChannels(channels: DeliveryChannelConfig[]): Promise<ChannelValidationResult[]> {
    this.logger.info('checkChannels called', { channelCount: channels.length });

    return Promise.all(channels.map((channel) => this.checkSingleChannel(channel)));
  }

  private async checkSingleChannel(channel: DeliveryChannelConfig): Promise<ChannelValidationResult> {
    try {
      return await this.withTimeout(this.performCheck(channel), VALIDATION_TIMEOUT_MS);
    } catch (error: unknown) {
      if (error instanceof TimeoutError) {
        return {
          channelType: channel.type,
          isValid: false,
          error: `Channel validation timed out after ${VALIDATION_TIMEOUT_MS / 1000} seconds`,
        };
      }
      const message = error instanceof Error ? error.message : String(error);
      return {
        channelType: channel.type,
        isValid: false,
        error: message.slice(0, 200),
      };
    }
  }

  private async performCheck(channel: DeliveryChannelConfig): Promise<ChannelValidationResult> {
    switch (channel.type) {
      case 'sns':
        return this.checkSnsChannel(channel);
      case 'slack':
        return this.checkCredentialChannel(channel);
      case 'jira':
        return this.checkCredentialChannel(channel);
      case 'servicenow':
        return this.checkCredentialChannel(channel);
      case 'email':
        return { channelType: 'email', isValid: true };
      default: {
        const unsupportedType: never = channel;
        return {
          channelType: (unsupportedType as DeliveryChannelConfig).type,
          isValid: false,
          error: `Unsupported channel type: ${(unsupportedType as DeliveryChannelConfig).type}`,
        };
      }
    }
  }

  private checkSnsChannel(channel: Extract<DeliveryChannelConfig, { type: 'sns' }>): ChannelValidationResult {
    if (!parseSnsTopicArn(channel.topicArn)) {
      return {
        channelType: 'sns',
        isValid: false,
        error: 'Invalid ARN format for SNS topic',
      };
    }
    return { channelType: 'sns', isValid: true };
  }

  private async checkCredentialChannel(
    channel: Extract<DeliveryChannelConfig, { type: 'slack' | 'jira' | 'servicenow' }>,
  ): Promise<ChannelValidationResult> {
    if (channel.type === 'jira' || channel.type === 'servicenow') {
      if (!channel.endpointUrl) {
        return { channelType: channel.type, isValid: false, error: 'Endpoint URL is required' };
      }
      const urlError = this.checkHttpsUrl(channel.endpointUrl);
      if (urlError) {
        return { channelType: channel.type, isValid: false, error: urlError };
      }
    }

    if (!secretsManagerArnSchema.safeParse(channel.credentialsSecretArn).success) {
      return {
        channelType: channel.type,
        isValid: false,
        error: `Invalid ARN format for ${channel.type} credentials`,
      };
    }

    try {
      await this.secretsClient.send(new GetSecretValueCommand({ SecretId: channel.credentialsSecretArn }));
    } catch (error: unknown) {
      const message = (error instanceof Error ? error.message : String(error)).slice(0, 200);
      return {
        channelType: channel.type,
        isValid: false,
        error: `Credentials secret not found or not accessible: ${message}`,
      };
    }

    return { channelType: channel.type, isValid: true };
  }

  private checkHttpsUrl(url: string): string | undefined {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:') {
        return 'Endpoint URL must use HTTPS protocol';
      }
      if (!parsed.hostname) {
        return 'Endpoint URL must include a hostname';
      }
      return undefined;
    } catch {
      return 'Endpoint URL is not a valid URL';
    }
  }

  private async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timeoutId = setTimeout(() => reject(new TimeoutError()), timeoutMs);
    });

    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      if (timeoutId !== undefined) {
        clearTimeout(timeoutId);
      }
    }
  }
}

/** Internal-only error used to distinguish timeout rejections within ChannelChecker. */
class TimeoutError extends Error {
  constructor() {
    super('Timeout');
    this.name = 'TimeoutError';
  }
}
