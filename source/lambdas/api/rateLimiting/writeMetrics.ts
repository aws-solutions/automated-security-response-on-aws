// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  emitMetric,
  SENSITIVE_WRITE_METRIC,
  CONTROL_STATE_CHANGE_METRIC,
  WRITE_CATEGORY_DIMENSION,
} from '../../common/utils/cloudWatchMetrics';
import { classifyRoute } from './routeTiers';

const CONTROL_BULK_EDIT_PATH = '/controls/bulk-edit';

/**
 * Emits write-volume metrics for a completed API request, used by the
 * anomalous-write CloudWatch alarms. Only successful (2xx) responses are
 * counted, so failed/throttled attempts do not inflate the signal.
 *
 *  - `SensitiveWriteRequest` (dimension `Category`) for `critical` and
 *    `sensitiveWrite` tier routes (user/notification/filter mutations,
 *    finding actions, control bulk-edits).
 *  - `ControlStateChangeRequest` (no dimensions) specifically for control
 *    bulk-edit requests — one per request, not per control, so a legitimate
 *    bulk operation that changes many controls counts as a single change.
 */
export function recordApiWriteMetrics(method: string, path: string, statusCode: number): void {
  if (statusCode < 200 || statusCode >= 300) {
    return;
  }

  const tier = classifyRoute(method, path);
  if (tier === 'critical' || tier === 'sensitiveWrite') {
    emitMetric(SENSITIVE_WRITE_METRIC, 1, [{ name: WRITE_CATEGORY_DIMENSION, value: tier }]);
  }

  if (method.toUpperCase() === 'POST' && path === CONTROL_BULK_EDIT_PATH) {
    emitMetric(CONTROL_STATE_CHANGE_METRIC, 1);
  }
}
