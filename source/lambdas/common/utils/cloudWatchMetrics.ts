// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Clock, getClock } from './clock';

/**
 * CloudWatch namespace for ASR custom metrics. Matches the namespace used by
 * the Python Orchestrator's PutMetricData metrics and referenced by the
 * CloudWatch alarms in the CDK stack.
 */
export const ASR_METRIC_NAMESPACE = 'ASR';

// Metric names. Kept as exported constants so the Lambda emitter and the alarm
// definitions (which reference the same names as string literals in the CDK
// package) stay aligned.
export const SENSITIVE_WRITE_METRIC = 'SensitiveWriteRequest';
export const CONTROL_STATE_CHANGE_METRIC = 'ControlStateChangeRequest';

/**
 * Emitted when a machine (client_credentials) token is denied Full Access for
 * lacking the `asr-api/full-access` scope. The CDK `ASR-Cognito-M2MForbidden`
 * alarm watches this metric (namespace `ASR`, dimension `UserPool`), so the name
 * and the dimension below must stay aligned with the alarm definition.
 */
export const M2M_FORBIDDEN_AUTHORIZATION_METRIC = 'M2MForbiddenAuthorization';

/**
 * Dimension name tagging the `M2MForbiddenAuthorization` metric with the Cognito
 * user pool id. Shared so the Lambda emitter and the CDK alarm reference the same
 * dimension key.
 */
export const USER_POOL_DIMENSION = 'UserPool';

/**
 * Dimension name tagging a `SensitiveWriteRequest` metric with its route tier
 * (`critical` / `sensitiveWrite`). Shared so the Lambda emitter and the CDK
 * alarm definitions reference the same dimension key.
 */
export const WRITE_CATEGORY_DIMENSION = 'Category';

export interface MetricDimension {
  readonly name: string;
  readonly value: string;
}

/**
 * Valid CloudWatch metric units. Constrains the `emitMetric` `unit` parameter
 * so invalid unit strings are caught at compile time rather than silently
 * producing a metric CloudWatch cannot interpret.
 */
export type MetricUnit =
  | 'Seconds'
  | 'Microseconds'
  | 'Milliseconds'
  | 'Bytes'
  | 'Kilobytes'
  | 'Megabytes'
  | 'Gigabytes'
  | 'Terabytes'
  | 'Bits'
  | 'Kilobits'
  | 'Megabits'
  | 'Gigabits'
  | 'Terabits'
  | 'Percent'
  | 'Count'
  | 'Bytes/Second'
  | 'Kilobytes/Second'
  | 'Megabytes/Second'
  | 'Gigabytes/Second'
  | 'Terabytes/Second'
  | 'Bits/Second'
  | 'Kilobits/Second'
  | 'Megabits/Second'
  | 'Gigabits/Second'
  | 'Terabits/Second'
  | 'Count/Second'
  | 'None';

/**
 * Emits a single CloudWatch metric using the embedded metric format (EMF).
 *
 * The EMF document is written directly to stdout (not via `console`) because
 * the Lambda runtime's text log format prefixes `console.*` output with a
 * timestamp and request id, which would invalidate the EMF parser's
 * requirement that the log line be a standalone JSON object. CloudWatch Logs
 * extracts the metric automatically — no IAM permission or API call needed.
 *
 * Emission never throws: observability must not break the request path.
 *
 * The clock is injectable (defaulting to the system clock) so tests can supply
 * a fixed timestamp without mocking the clock module.
 */
export function emitMetric(
  metricName: string,
  value: number,
  dimensions: readonly MetricDimension[] = [],
  unit: MetricUnit = 'Count',
  clock: Clock = getClock(),
): void {
  try {
    const dimensionKeys = dimensions.map((dimension) => dimension.name);
    const document: Record<string, unknown> = {
      _aws: {
        Timestamp: clock.now().getTime(),
        CloudWatchMetrics: [
          {
            Namespace: ASR_METRIC_NAMESPACE,
            // A single empty dimension set ([[]]) publishes the metric with no
            // dimensions; a populated set publishes one dimensioned metric.
            Dimensions: [dimensionKeys],
            Metrics: [{ Name: metricName, Unit: unit }],
          },
        ],
      },
      [metricName]: value,
    };
    for (const dimension of dimensions) {
      document[dimension.name] = dimension.value;
    }
    process.stdout.write(`${JSON.stringify(document)}\n`);
  } catch (error) {
    // A metrics failure must never affect the request, so we swallow it. Log to
    // stderr (not stdout, which is the EMF channel) so that a broken metrics
    // pipeline is still observable to operators.
    try {
      console.error(`Failed to emit metric ${metricName}`, error);
    } catch {
      // Ignore: even error logging must not break the request path.
    }
  }
}
