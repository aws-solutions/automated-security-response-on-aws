// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBTestSetup } from './dynamodbSetup';

beforeAll(async () => {
  await DynamoDBTestSetup.initialize();
  await DynamoDBTestSetup.cleanup();
});

afterAll(async () => {
  jest.restoreAllMocks();
  await DynamoDBTestSetup.cleanup();
});
