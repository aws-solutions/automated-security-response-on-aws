// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DeployWebUIEnvironmentConfig } from '@asr/data-models';
import { readOptionalEnvironmentVariables, requireEnvironmentVariables } from '../../common/utils/env-variables';

/**
 * The subset of {@link DeployWebUIEnvironmentConfig} the deploy Lambda reads at runtime:
 * CONFIG (required) carries the WebUI configuration JSON; CLOUDFRONT_DISTRIBUTION_ID is
 * optional here because an empty/absent value means the WebUI is not fronted by CloudFront
 * and the post-deploy cache invalidation is skipped.
 */
export type DeployWebUIRuntimeConfig = Pick<DeployWebUIEnvironmentConfig, 'CONFIG'> &
  Partial<Pick<DeployWebUIEnvironmentConfig, 'CLOUDFRONT_DISTRIBUTION_ID'>>;

/**
 * Reads and validates the deploy Lambda's environment: CONFIG is required,
 * CLOUDFRONT_DISTRIBUTION_ID is optional. Read on each call rather than cached so a
 * warm container reflects the values present for the invocation it is handling.
 */
export function deployWebuiEnvironment(): DeployWebUIRuntimeConfig {
  return {
    ...requireEnvironmentVariables(['CONFIG'] as const),
    ...readOptionalEnvironmentVariables(['CLOUDFRONT_DISTRIBUTION_ID'] as const),
  };
}
