// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export type SuppressionResult = {
  suppressed: boolean;
};

export type RemediationResult = {
  remediationStatus: 'IN_PROGRESS' | 'FAILED';
  executionIdsByFindingId?: Map<string, string>;
  error?: string;
};

export type ActionResult = SuppressionResult | RemediationResult;
