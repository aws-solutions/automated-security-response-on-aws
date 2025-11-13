// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBClient, DynamoDBClientConfig } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { NodeHttpHandler } from '@smithy/node-http-handler';

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
