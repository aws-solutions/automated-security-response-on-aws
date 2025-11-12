// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ResourceNotFoundException } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { Logger } from '@aws-lambda-powertools/logger';

/** Checks remediation configuration for security controls with caching to avoid duplicate DynamoDB calls */
export class RemediationConfigChecker {
  private cachedItem: Record<string, any> | null = null;

  /** @param controlId Security control ID to check
   * @param dynamoDBDocumentClient DynamoDB document client instance
   * @param logger
   * @param tableName Remediation configuration table name */
  constructor(
    private readonly controlId: string,
    private readonly dynamoDBDocumentClient: DynamoDBDocumentClient,
    private readonly tableName: string,
    private readonly logger: Logger,
  ) {}

  /** Fetches and caches the remediation config item from DynamoDB */
  private async getItem(): Promise<Record<string, any> | null> {
    if (this.cachedItem !== null) {
      return this.cachedItem;
    }

    try {
      const command = new GetCommand({
        TableName: this.tableName,
        Key: {
          controlId: this.controlId,
        },
      });

      const result = await this.dynamoDBDocumentClient.send(command);
      this.cachedItem = result.Item || null;
      return this.cachedItem;
    } catch (error) {
      if (error instanceof ResourceNotFoundException) {
        this.logger.debug(
          `Could not find ${this.controlId} in Remediation Configuration table, indicating the control is not supported in ASR.`,
          { error, controlId: this.controlId },
        );
        this.cachedItem = null;
        return null;
      }
      this.logger.error('Error accessing remediation configuration', { error, controlId: this.controlId });
      throw error;
    }
  }

  /** Returns true if the control exists in the remediation configuration table */
  async isSupported(): Promise<boolean> {
    const item = await this.getItem();
    return !!item;
  }

  /** Returns true if automated remediation is enabled for this control */
  async isAutomatedRemediationEnabled(): Promise<boolean> {
    const item = await this.getItem();
    return item?.automatedRemediationEnabled === true;
  }
}
