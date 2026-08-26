// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ChannelLambdaEnvironmentConfig } from '@asr/data-models';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../common/utils/env-variables';

let cached: ChannelLambdaEnvironmentConfig | undefined;
let cachedRuntimeEnv: { readonly AWS_REGION: string } | undefined;

const REQUIRED_KEYS: readonly (keyof ChannelLambdaEnvironmentConfig)[] = [
  'SOLUTION_TRADEMARKEDNAME',
  'POWERTOOLS_LOG_LEVEL',
  'AWS_ACCOUNT_ID',
  'AWS_PARTITION',
  'STACK_ID',
  'RESOURCE_NAME_PREFIX',
  'IAC_TEMPLATES_BUCKET',
] as const;

const OPTIONAL_KEYS = ['WEB_UI_URL'] as const;

export function channelLambdaEnvironment(): ChannelLambdaEnvironmentConfig {
  if (cached) return cached;
  cached = {
    ...requireEnvironmentVariables(REQUIRED_KEYS),
    ...readOptionalEnvironmentVariables(OPTIONAL_KEYS),
  };
  return cached;
}

export function channelLambdaRuntimeEnvironment(): { readonly AWS_REGION: string } {
  if (cachedRuntimeEnv) return cachedRuntimeEnv;
  cachedRuntimeEnv = requireEnvironmentVariables(['AWS_REGION'] as const);
  return cachedRuntimeEnv;
}

export function resetChannelLambdaEnvironmentCache(): void {
  cached = undefined;
  cachedRuntimeEnv = undefined;
}
