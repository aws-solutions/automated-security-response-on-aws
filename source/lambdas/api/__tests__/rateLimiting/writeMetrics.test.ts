// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { recordApiWriteMetrics } from '../../rateLimiting/writeMetrics';
import {
  ASR_METRIC_NAMESPACE,
  SENSITIVE_WRITE_METRIC,
  CONTROL_STATE_CHANGE_METRIC,
} from '../../../common/utils/cloudWatchMetrics';

interface EmfMetricDirective {
  Namespace: string;
  Dimensions: string[][];
  Metrics: { Name: string; Unit?: string }[];
}

interface EmfDocument {
  _aws: { Timestamp: number; CloudWatchMetrics: EmfMetricDirective[] };
  [key: string]: unknown;
}

describe('recordApiWriteMetrics', () => {
  let writeSpy: jest.SpyInstance;

  beforeEach(() => {
    writeSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    writeSpy.mockRestore();
  });

  // Parse every EMF document written to stdout during a test. Spying on the
  // real boundary (process.stdout.write) exercises recordApiWriteMetrics and
  // emitMetric together, as they run in production.
  function emittedDocuments(): EmfDocument[] {
    return writeSpy.mock.calls.map((call) => JSON.parse((call[0] as string).trim()));
  }

  function documentForMetric(metricName: string): EmfDocument | undefined {
    return emittedDocuments().find((doc) => doc._aws.CloudWatchMetrics[0].Metrics[0].Name === metricName);
  }

  it('emits a sensitive-write and a control-state-change metric for a successful bulk-edit', () => {
    // ARRANGE / ACT: control bulk-edit is a critical-tier write
    recordApiWriteMetrics('POST', '/controls/bulk-edit', 200);

    // ASSERT: both metrics emitted, sensitive-write tagged with the tier category
    const sensitiveWriteDoc = documentForMetric(SENSITIVE_WRITE_METRIC);
    if (!sensitiveWriteDoc) throw new Error(`Expected ${SENSITIVE_WRITE_METRIC} metric to be emitted`);
    expect(sensitiveWriteDoc._aws.CloudWatchMetrics[0].Namespace).toBe(ASR_METRIC_NAMESPACE);
    expect(sensitiveWriteDoc._aws.CloudWatchMetrics[0].Dimensions).toEqual([['Category']]);
    expect(sensitiveWriteDoc.Category).toBe('critical');
    expect(sensitiveWriteDoc[SENSITIVE_WRITE_METRIC]).toBe(1);

    const controlStateChangeDoc = documentForMetric(CONTROL_STATE_CHANGE_METRIC);
    if (!controlStateChangeDoc) throw new Error(`Expected ${CONTROL_STATE_CHANGE_METRIC} metric to be emitted`);
    expect(controlStateChangeDoc[CONTROL_STATE_CHANGE_METRIC]).toBe(1);
  });

  it('counts a partial-success (207) bulk-edit as a state change', () => {
    // ARRANGE / ACT
    recordApiWriteMetrics('POST', '/controls/bulk-edit', 207);

    // ASSERT
    expect(documentForMetric(CONTROL_STATE_CHANGE_METRIC)?.[CONTROL_STATE_CHANGE_METRIC]).toBe(1);
  });

  it('emits only the sensitive-write metric for a sensitiveWrite-tier route', () => {
    // ARRANGE / ACT: creating a notification config is sensitiveWrite, not a control change
    recordApiWriteMetrics('POST', '/notifications', 201);

    // ASSERT
    const sensitiveWriteDoc = documentForMetric(SENSITIVE_WRITE_METRIC);
    expect(sensitiveWriteDoc?.Category).toBe('sensitiveWrite');
    expect(sensitiveWriteDoc?.[SENSITIVE_WRITE_METRIC]).toBe(1);
    expect(documentForMetric(CONTROL_STATE_CHANGE_METRIC)).toBeUndefined();
  });

  it('does not emit for read-tier routes or non-2xx responses', () => {
    // ARRANGE / ACT
    recordApiWriteMetrics('GET', '/controls', 200); // read tier
    recordApiWriteMetrics('POST', '/controls/bulk-edit', 409); // conflict, no state change
    recordApiWriteMetrics('POST', '/controls/bulk-edit', 429); // throttled

    // ASSERT
    expect(writeSpy).not.toHaveBeenCalled();
  });
});
