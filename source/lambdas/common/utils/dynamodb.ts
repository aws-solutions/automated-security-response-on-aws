// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DynamoDBClient,
  DynamoDBClientConfig,
  ItemCollectionSizeLimitExceededException,
} from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { NodeHttpHandler } from '@smithy/node-http-handler';

const ITEM_COLLECTION_SIZE_EXCEEDED_MESSAGE = /collection size exceeded/i;

/**
 * Returns true when a DynamoDB write was rejected because the item collection (every item sharing
 * one partition-key value, in a table that has a local secondary index) has reached DynamoDB's
 * 10 GB cap. Writes to that partition keep failing until the collection shrinks, so callers must not
 * retry them.
 *
 * The modeled SDK class is checked first. The message fallback exists because the same rejection
 * has been observed in production surfaced as a `ValidationException` carrying the message
 * "Collection size exceeded", which the modeled class does not cover.
 */
export function isItemCollectionSizeLimitError(error: unknown): boolean {
  if (error instanceof ItemCollectionSizeLimitExceededException) return true;
  if (!(error instanceof Error)) return false;
  const isDynamoDbRejection =
    error.name === 'ItemCollectionSizeLimitExceededException' || error.name === 'ValidationException';
  return isDynamoDbRejection && ITEM_COLLECTION_SIZE_EXCEEDED_MESSAGE.test(error.message);
}

export function createDynamoDBClient(config: DynamoDBClientConfig = {}): DynamoDBDocumentClient {
  const finalConfig: DynamoDBClientConfig = {
    ...config,
    ...(process.env.DYNAMODB_ENDPOINT &&
      !config.endpoint && {
        endpoint: process.env.DYNAMODB_ENDPOINT,
      }),
  };

  // Configure connection pooling to prevent EMFILE errors only if not already configured
  if (!finalConfig.requestHandler) {
    finalConfig.requestHandler = new NodeHttpHandler({
      connectionTimeout: 3000,
      requestTimeout: 3000,
      httpsAgent: {
        maxSockets: 50,
        keepAlive: true,
        keepAliveMsecs: 1000,
      },
    });
  }

  return DynamoDBDocumentClient.from(new DynamoDBClient(finalConfig));
}

/**
 * Converts a DynamoDB String Set (SS) or array to a plain string array.
 * DynamoDB returns Set<string> for SS attributes, but JSON serialization requires arrays.
 */
export function toStringArray(value: Set<string> | string[] | undefined): string[] {
  if (!value) return [];
  if (value instanceof Set) return Array.from(value);
  if (Array.isArray(value)) return value;
  return [];
}
