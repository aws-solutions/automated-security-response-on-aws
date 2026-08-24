// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Stack } from 'aws-cdk-lib';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Function as LambdaFunction } from 'aws-cdk-lib/aws-lambda';

/**
 * Grants a Lambda the SSM parameter permissions required by `sendMetrics()`
 * (`common/utils/metricsUtils.ts`) when publishing anonymous usage metrics to
 * the SolutionsMetrics API. Permissions are scoped to least privilege to match
 * exactly how `sendMetrics()` uses each parameter:
 * - read on all three parameters (solution version, current and deprecated UUID),
 * - write only on the current `metrics_uuid` parameter (set when not already present),
 * - delete only on the deprecated `anonymous_metrics_uuid` parameter (cleanup).
 */
export function addMetricsSsmPermissions(fn: LambdaFunction, solutionId: string): void {
  const stack = Stack.of(fn);
  const parameterArn = (parameterName: string): string =>
    `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${solutionId}/${parameterName}`;

  const deprecatedUuidArn = parameterArn('anonymous_metrics_uuid');
  const metricsUuidArn = parameterArn('metrics_uuid');
  const versionArn = parameterArn('version');

  fn.addToRolePolicy(
    new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['ssm:GetParameter'],
      resources: [deprecatedUuidArn, metricsUuidArn, versionArn],
    }),
  );

  fn.addToRolePolicy(
    new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['ssm:PutParameter'],
      resources: [metricsUuidArn],
    }),
  );

  fn.addToRolePolicy(
    new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['ssm:DeleteParameter'],
      resources: [deprecatedUuidArn],
    }),
  );
}
