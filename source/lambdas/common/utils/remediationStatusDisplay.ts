// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** Returns the most specific remediation status available for display in notifications and CSV. */
export function getDisplayRemediationStatus(finding: {
  remediationStatus?: string;
  remediationStatusDetail?: string;
}): string {
  return finding.remediationStatusDetail || finding.remediationStatus || '';
}
