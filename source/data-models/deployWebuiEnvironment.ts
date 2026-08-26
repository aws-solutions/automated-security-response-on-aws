// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared interface defining the environment variables passed from CDK to the
 * WebUI deployment custom-resource Lambda. Both the CDK construct and the Lambda
 * accessor reference this type so the compiler catches any drift between the two
 * sides.
 */
export interface DeployWebUIEnvironmentConfig {
  readonly LOG_LEVEL: string;
  readonly CONFIG: string;
  readonly POWERTOOLS_SERVICE_NAME: string;
  readonly SOLUTION_VERSION: string;
  readonly STACK_ID: string;
  readonly AWS_ACCOUNT_ID: string;
  /**
   * Id of the CloudFront distribution fronting the WebUI. After copying assets the
   * deploy Lambda invalidates the non-content-hashed paths on this distribution; an
   * empty value skips invalidation.
   */
  readonly CLOUDFRONT_DISTRIBUTION_ID: string;
}
