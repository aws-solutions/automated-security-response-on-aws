// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SecurityControl } from '@asr/data-models';

export interface RemediationToggle {
  readonly action: 'CONTROL_REMEDIATION_SET' | 'CONTROL_REMEDIATION_ENABLED';
  readonly affectedControlCount: number;
}

export interface RollbackToggle {
  readonly action: 'CONTROL_ROLLBACK_SET' | 'CONTROL_ROLLBACK_ENABLED';
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

/**
 * The rollback equivalent of computeRemediationToggle: determines whether a bulk control update
 * actually changed the rollback toggle, and grades it as a disable (high severity) when any control
 * in the set was turned off, otherwise as an enable. Returns undefined when no control's rollback
 * state changed. rollbackEnabled is optional and an absent value counts as enabled — matching the
 * Orchestrator gate, the repository read, and the WebUI's own change detection — so both the update
 * and the prior state are normalised before comparing. A control absent from the prior state (created
 * in this same edit) is not treated as a toggle.
 */
export function computeRollbackToggle(
  successfulControls: readonly SecurityControl[],
  previousRollbackByControlId: ReadonlyMap<string, boolean>,
): RollbackToggle | undefined {
  const rollbackToggled = successfulControls.filter((control) => {
    const previous = previousRollbackByControlId.get(control.controlId);
    if (previous === undefined) return false;
    // Normalise absent rollbackEnabled to enabled on both sides before comparing.
    return (control.rollbackEnabled !== false) !== previous;
  });
  if (rollbackToggled.length === 0) return undefined;

  const rollbackDisabled = rollbackToggled.some((control) => control.rollbackEnabled === false);
  return {
    action: rollbackDisabled ? 'CONTROL_ROLLBACK_SET' : 'CONTROL_ROLLBACK_ENABLED',
    affectedControlCount: rollbackToggled.length,
  };
}
