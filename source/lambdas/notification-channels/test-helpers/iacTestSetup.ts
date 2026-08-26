// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { resetChannelLambdaEnvironmentCache } from '../channelLambdaEnvironment';

export function setupIaCTestEnvironment(): void {
  resetChannelLambdaEnvironmentCache();
  process.env.WEB_UI_URL = 'https://ui.example.com';
  process.env.SOLUTION_VERSION = 'v1.0.0';
  process.env.SOLUTION_TRADEMARKEDNAME = 'ASR';
  process.env.POWERTOOLS_LOG_LEVEL = 'SILENT';
  process.env.AWS_PARTITION = 'aws';
  process.env.STACK_ID = 'test-stack';
  process.env.RESOURCE_NAME_PREFIX = 'SO0111';
  process.env.IAC_TEMPLATES_BUCKET = 'test-bucket';
}

export function teardownIaCTestEnvironment(): void {
  delete process.env.WEB_UI_URL;
  resetChannelLambdaEnvironmentCache();
}
