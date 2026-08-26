// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export interface ChannelLambdaEnvironmentConfig {
  readonly SOLUTION_TRADEMARKEDNAME: string;
  readonly POWERTOOLS_LOG_LEVEL: string;
  readonly AWS_ACCOUNT_ID: string;
  readonly AWS_PARTITION: string;
  readonly STACK_ID: string;
  readonly RESOURCE_NAME_PREFIX: string;
  readonly WEB_UI_URL?: string;
  readonly IAC_TEMPLATES_BUCKET: string;
}
