// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ResourceNotFoundException } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { Logger } from '@aws-lambda-powertools/logger';
import { FilterMode, SecurityControlDynamoDBItem } from '@asr/data-models';

export interface ControlConfig {
  automatedRemediationEnabled: boolean;
  filters: string[];
  filterMode: FilterMode;
}

function isSecurityControlDynamoDBItem(item: unknown): item is SecurityControlDynamoDBItem {
  return (
    item !== null &&
    typeof item === 'object' &&
    'controlId' in item &&
    typeof (item as Record<string, unknown>).controlId === 'string' &&
    'automatedRemediationEnabled' in item &&
    typeof (item as Record<string, unknown>).automatedRemediationEnabled === 'boolean'
  );
}

/** Checks remediation configuration for security controls with caching to avoid duplicate DynamoDB calls */
export class RemediationConfigChecker {
  private cachedItem: SecurityControlDynamoDBItem | null = null;

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
  private async getItem(): Promise<SecurityControlDynamoDBItem | null> {
    if (this.cachedItem !== null) {
      return this.cachedItem;
    }

    // A blank control id can't match any config row, so treat it as unsupported
    // instead of issuing a GetItem that DynamoDB rejects for the empty key.
    // Multi-service findings are unaffected: they resolve to a non-empty
    // remediation id (e.g. Inspector.InstanceVulnerability) before reaching here.
    if (this.controlId.trim() === '') {
      this.logger.debug('Finding has no resolvable control id; treating the control as unsupported.');
      return null;
    }

    try {
      const command = new GetCommand({
        TableName: this.tableName,
        Key: {
          controlId: this.controlId,
        },
      });

      const result = await this.dynamoDBDocumentClient.send(command);
      if (result.Item && isSecurityControlDynamoDBItem(result.Item)) {
        this.cachedItem = result.Item;
      } else {
        if (result.Item) {
          this.logger.warn(
            `Item found for ${this.controlId} but failed type validation. The control will be treated as unsupported.`,
            { controlId: this.controlId, item: result.Item },
          );
        }
        this.cachedItem = null;
      }
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

  /** Returns the full control configuration including filters and filterMode */
  async getControlConfig(): Promise<ControlConfig | null> {
    const item = await this.getItem();
    if (!item) {
      return null;
    }

    let filters: string[] = [];
    if (item.filters) {
      filters = item.filters instanceof Set ? Array.from(item.filters) : item.filters;
    }

    return {
      automatedRemediationEnabled: item.automatedRemediationEnabled,
      filters,
      filterMode: item.filterMode ?? 'include',
    };
  }
}
