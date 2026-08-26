// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityControl } from '@asr/data-models';

export interface RemediationToggle {
  readonly action: 'CONTROL_REMEDIATION_SET' | 'CONTROL_REMEDIATION_ENABLED';
  readonly affectedControlCount: number;
}

/**
 * Determines whether a bulk control update actually changed automated remediation, and if so how to
 * grade it. Bulk-edit requests carry the full control object including unchanged fields, so the
 * prior state (keyed by control id) is required to tell a real remediation toggle apart from an edit
 * that only touched filters or other fields. Returns undefined when no control's remediation state
 * changed. The toggled set is graded as a disable (high severity) when any control in it was turned
 * off, otherwise as an enable.
 */
export function computeRemediationToggle(
  successfulControls: readonly SecurityControl[],
  previousRemediationByControlId: ReadonlyMap<string, boolean>,
): RemediationToggle | undefined {
  const remediationToggled = successfulControls.filter(
    (control) => control.automatedRemediationEnabled !== previousRemediationByControlId.get(control.controlId),
  );
  if (remediationToggled.length === 0) return undefined;

  const remediationDisabled = remediationToggled.some((control) => control.automatedRemediationEnabled === false);
  return {
    action: remediationDisabled ? 'CONTROL_REMEDIATION_SET' : 'CONTROL_REMEDIATION_ENABLED',
    affectedControlCount: remediationToggled.length,
  };
}
