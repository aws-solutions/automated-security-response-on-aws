// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import type { FindingApiResponse } from '@data-models';
import {
  SELECTION_LIMIT,
  isFindingIneligibleForSelection,
  isRowSelectionDisabled,
  limitFindingSelection,
} from '../../../pages/findings/findings-table/FindingsTable';
import { batchItems } from '../../../pages/findings/findings-table/findingsActionBatch';
import { asFindingId, generateTestFinding } from '../../test-data-factory';

describe('batchItems', () => {
  it.each<{ scenario: string; length: number; batchSize: number; expectedSizes: number[] }>([
    { scenario: 'an exact multiple of the batch size', length: 30, batchSize: 15, expectedSizes: [15, 15] },
    {
      scenario: 'a non-multiple with a smaller final remainder',
      length: 32,
      batchSize: 15,
      expectedSizes: [15, 15, 2],
    },
    { scenario: 'fewer items than the batch size', length: 4, batchSize: 15, expectedSizes: [4] },
    { scenario: 'an empty array', length: 0, batchSize: 15, expectedSizes: [] },
  ])('splits $scenario into consecutive chunks', ({ length, batchSize, expectedSizes }) => {
    // GIVEN a sequential list of numbers
    const items = Array.from({ length }, (_, index) => index);

    // WHEN the list is split into batches
    const batches = batchItems(items, batchSize);

    // THEN the chunk sizes match and no chunk exceeds the batch size
    expect(batches.map((batch) => batch.length)).toEqual(expectedSizes);
    batches.forEach((batch) => expect(batch.length).toBeLessThanOrEqual(batchSize));
  });

  it('preserves order and partitions every item exactly once', () => {
    // GIVEN a sequential list that does not divide evenly by the batch size
    const items = Array.from({ length: 32 }, (_, index) => index);

    // WHEN the list is split and then flattened back together
    const flattened = batchItems(items, 15).flat();

    // THEN the flattened batches equal the original list in the original order
    expect(flattened).toEqual(items);
  });
});

describe('isFindingIneligibleForSelection', () => {
  it.each<[FindingApiResponse['remediationStatus'], boolean]>([
    ['IN_PROGRESS', true],
    ['SUCCESS', true],
    ['NOT_STARTED', false],
  ])('treats a %s finding as ineligible=%s', (remediationStatus, expected) => {
    // GIVEN a finding with a specific remediation status
    const finding = generateTestFinding({
      findingId: asFindingId(`finding-${remediationStatus}`),
      remediationStatus,
    });

    // WHEN eligibility is evaluated
    const ineligible = isFindingIneligibleForSelection(finding);

    // THEN only IN_PROGRESS and SUCCESS findings are ineligible
    expect(ineligible).toBe(expected);
  });
});

describe('isRowSelectionDisabled', () => {
  // A full-cap selection of eligible, distinctly-identified findings. The first
  // entry doubles as an "already selected" fixture for the at-limit rows.
  const selectionAtLimit: FindingApiResponse[] = Array.from({ length: SELECTION_LIMIT }, (_, index) =>
    generateTestFinding({ findingId: asFindingId(`selected-${index}`), remediationStatus: 'NOT_STARTED' }),
  );
  const alreadySelectedFinding = selectionAtLimit[0];
  const selectionBelowCap = selectionAtLimit.slice(0, 3);

  const unselectedEligibleFinding = generateTestFinding({
    findingId: asFindingId('unselected-eligible'),
    remediationStatus: 'NOT_STARTED',
  });
  const ineligibleFinding = generateTestFinding({
    findingId: asFindingId('ineligible-in-progress'),
    remediationStatus: 'IN_PROGRESS',
  });

  it.each<{ scenario: string; finding: FindingApiResponse; selectedItems: FindingApiResponse[]; expected: boolean }>([
    {
      scenario: 'disables an ineligible finding regardless of the selection count',
      finding: ineligibleFinding,
      selectedItems: [],
      expected: true,
    },
    {
      scenario: 'keeps an eligible unselected row selectable below the cap',
      finding: unselectedEligibleFinding,
      selectedItems: selectionBelowCap,
      expected: false,
    },
    {
      scenario: 'disables an unselected eligible row once the limit is reached',
      finding: unselectedEligibleFinding,
      selectedItems: selectionAtLimit,
      expected: true,
    },
    {
      scenario: 'keeps an already-selected row selectable at exactly the limit',
      finding: alreadySelectedFinding,
      selectedItems: selectionAtLimit,
      expected: false,
    },
  ])('$scenario', ({ finding, selectedItems, expected }) => {
    // GIVEN a finding, the current selection, and the cap

    // WHEN the row-disable predicate is evaluated
    const disabled = isRowSelectionDisabled(finding, selectedItems, SELECTION_LIMIT);

    // THEN the row is disabled iff it is ineligible, or the cap is reached and it is not selected
    expect(disabled).toBe(expected);
  });

  it('disables every row when the whole displayed list is ineligible', () => {
    // GIVEN a displayed list where every finding is ineligible
    const allIneligible: FindingApiResponse[] = [
      generateTestFinding({ findingId: asFindingId('all-ineligible-in-progress'), remediationStatus: 'IN_PROGRESS' }),
      generateTestFinding({ findingId: asFindingId('all-ineligible-success'), remediationStatus: 'SUCCESS' }),
    ];

    // WHEN each row's disable state is evaluated with an empty selection
    const disabledStates = allIneligible.map((finding) => isRowSelectionDisabled(finding, [], SELECTION_LIMIT));

    // THEN every row is disabled
    expect(disabledStates).toEqual([true, true]);
  });
});

describe('limitFindingSelection', () => {
  const OVER_LIMIT_COUNT = SELECTION_LIMIT + 1;

  // Build `count` eligible findings in a fixed display order, each with a
  // distinct branded id. A list of SELECTION_LIMIT + 1 eligible findings is
  // enough to exercise both boundary directions.
  function buildEligibleFindings(count: number, prefix = 'eligible'): FindingApiResponse[] {
    return Array.from({ length: count }, (_, index) =>
      generateTestFinding({ findingId: asFindingId(`${prefix}-${index}`), remediationStatus: 'NOT_STARTED' }),
    );
  }

  // Report every displayed finding as selected — the select-all interaction.
  const reportEveryDisplayedFinding = (findings: FindingApiResponse[]): FindingApiResponse[] => [...findings];

  describe('never stores more findings than the cap', () => {
    const overLimitEligible = buildEligibleFindings(OVER_LIMIT_COUNT);
    const underLimitEligible = buildEligibleFindings(3);
    const allIneligible: FindingApiResponse[] = [
      generateTestFinding({ findingId: asFindingId('cap-in-progress'), remediationStatus: 'IN_PROGRESS' }),
      generateTestFinding({ findingId: asFindingId('cap-success'), remediationStatus: 'SUCCESS' }),
    ];

    it.each<{ scenario: string; findings: FindingApiResponse[]; reportedSelection: FindingApiResponse[] }>([
      {
        scenario: 'select-all over more eligible rows than the cap',
        findings: overLimitEligible,
        reportedSelection: reportEveryDisplayedFinding(overLimitEligible),
      },
      {
        scenario: 'select-all under the cap',
        findings: underLimitEligible,
        reportedSelection: reportEveryDisplayedFinding(underLimitEligible),
      },
      {
        scenario: 'an empty reported selection',
        findings: overLimitEligible,
        reportedSelection: [],
      },
      {
        scenario: 'select-all over an all-ineligible list',
        findings: allIneligible,
        reportedSelection: reportEveryDisplayedFinding(allIneligible),
      },
    ])('keeps the result within the cap for $scenario', ({ findings, reportedSelection }) => {
      // GIVEN a displayed list and a reported selection

      // WHEN the reported selection is reduced to what the table will hold
      const result = limitFindingSelection(reportedSelection, findings, SELECTION_LIMIT);

      // THEN the stored selection never exceeds the cap
      expect(result.length).toBeLessThanOrEqual(SELECTION_LIMIT);
    });
  });

  describe('never stores an ineligible finding', () => {
    const eligibleOne = generateTestFinding({
      findingId: asFindingId('excl-eligible-1'),
      remediationStatus: 'NOT_STARTED',
    });
    const inProgress = generateTestFinding({
      findingId: asFindingId('excl-in-progress'),
      remediationStatus: 'IN_PROGRESS',
    });
    const eligibleTwo = generateTestFinding({
      findingId: asFindingId('excl-eligible-2'),
      remediationStatus: 'NOT_STARTED',
    });
    const success = generateTestFinding({ findingId: asFindingId('excl-success'), remediationStatus: 'SUCCESS' });
    const mixed: FindingApiResponse[] = [eligibleOne, inProgress, eligibleTwo, success];
    const allIneligible: FindingApiResponse[] = [
      generateTestFinding({ findingId: asFindingId('excl-only-in-progress'), remediationStatus: 'IN_PROGRESS' }),
      generateTestFinding({ findingId: asFindingId('excl-only-success'), remediationStatus: 'SUCCESS' }),
    ];

    it.each<{ scenario: string; findings: FindingApiResponse[]; reportedSelection: FindingApiResponse[] }>([
      {
        scenario: 'select-all over a mix of eligible and ineligible rows',
        findings: mixed,
        reportedSelection: reportEveryDisplayedFinding(mixed),
      },
      {
        scenario: 'a reported selection that names only ineligible ids',
        findings: mixed,
        reportedSelection: [inProgress, success],
      },
      {
        scenario: 'select-all over an all-ineligible list',
        findings: allIneligible,
        reportedSelection: reportEveryDisplayedFinding(allIneligible),
      },
    ])('excludes IN_PROGRESS and SUCCESS findings for $scenario', ({ findings, reportedSelection }) => {
      // GIVEN a displayed list containing ineligible findings

      // WHEN the reported selection is reduced
      const result = limitFindingSelection(reportedSelection, findings, SELECTION_LIMIT);

      // THEN no stored finding is IN_PROGRESS or SUCCESS
      const hasIneligible = result.some(
        (finding) => finding.remediationStatus === 'IN_PROGRESS' || finding.remediationStatus === 'SUCCESS',
      );
      expect(hasIneligible).toBe(false);
    });
  });

  describe('select-all beyond the cap keeps the first eligible rows in display order', () => {
    const overLimitEligible = buildEligibleFindings(OVER_LIMIT_COUNT);
    const bodyEligible = buildEligibleFindings(OVER_LIMIT_COUNT, 'body');
    const leadingIneligible = generateTestFinding({
      findingId: asFindingId('lead-in-progress'),
      remediationStatus: 'IN_PROGRESS',
    });
    const ineligibleInterspersed = [leadingIneligible, ...bodyEligible];

    it.each<{ scenario: string; findings: FindingApiResponse[]; expected: FindingApiResponse[] }>([
      {
        scenario: 'a purely eligible over-limit list',
        findings: overLimitEligible,
        expected: overLimitEligible.slice(0, SELECTION_LIMIT),
      },
      {
        scenario: 'an over-limit list with an ineligible row interspersed',
        findings: ineligibleInterspersed,
        expected: bodyEligible.slice(0, SELECTION_LIMIT),
      },
    ])('returns the first cap eligible findings in display order for $scenario', ({ findings, expected }) => {
      // GIVEN a displayed list whose eligible subset exceeds the cap

      // WHEN every displayed finding is reported as selected
      const result = limitFindingSelection(reportEveryDisplayedFinding(findings), findings, SELECTION_LIMIT);

      // THEN the result is exactly the first cap eligible findings in display order
      expect(result).toEqual(expected);
      expect(result.length).toBe(SELECTION_LIMIT);
    });
  });

  describe('select-all at or under the cap keeps every eligible finding in display order', () => {
    const underEligibleOne = generateTestFinding({
      findingId: asFindingId('under-eligible-1'),
      remediationStatus: 'NOT_STARTED',
    });
    const underInProgress = generateTestFinding({
      findingId: asFindingId('under-in-progress'),
      remediationStatus: 'IN_PROGRESS',
    });
    const underEligibleTwo = generateTestFinding({
      findingId: asFindingId('under-eligible-2'),
      remediationStatus: 'NOT_STARTED',
    });
    const underSuccess = generateTestFinding({ findingId: asFindingId('under-success'), remediationStatus: 'SUCCESS' });
    const underEligibleThree = generateTestFinding({
      findingId: asFindingId('under-eligible-3'),
      remediationStatus: 'NOT_STARTED',
    });
    const underLimitMixed: FindingApiResponse[] = [
      underEligibleOne,
      underInProgress,
      underEligibleTwo,
      underSuccess,
      underEligibleThree,
    ];
    const exactAtLimitEligible = buildEligibleFindings(SELECTION_LIMIT, 'exact');

    it.each<{ scenario: string; findings: FindingApiResponse[]; expected: FindingApiResponse[] }>([
      {
        scenario: 'fewer eligible findings than the cap, with ineligible rows dropped',
        findings: underLimitMixed,
        expected: [underEligibleOne, underEligibleTwo, underEligibleThree],
      },
      {
        scenario: 'an eligible set exactly at the cap',
        findings: exactAtLimitEligible,
        expected: exactAtLimitEligible,
      },
    ])('returns every eligible finding in display order for $scenario', ({ findings, expected }) => {
      // GIVEN a displayed list whose eligible subset is at or below the cap

      // WHEN every displayed finding is reported as selected
      const result = limitFindingSelection(reportEveryDisplayedFinding(findings), findings, SELECTION_LIMIT);

      // THEN every eligible finding is kept in display order and ineligible rows are dropped
      expect(result).toEqual(expected);
    });

    it('keeps the result length at exactly the cap on the boundary', () => {
      // GIVEN an eligible set of exactly the cap size

      // WHEN select-all is reported
      const result = limitFindingSelection(
        reportEveryDisplayedFinding(exactAtLimitEligible),
        exactAtLimitEligible,
        SELECTION_LIMIT,
      );

      // THEN the stored length is exactly the cap, not one past it
      expect(result.length).toBe(SELECTION_LIMIT);
    });
  });

  describe('returns an empty selection when nothing eligible is reported', () => {
    const displayedEligible = buildEligibleFindings(3, 'empty-displayed');
    const allIneligible: FindingApiResponse[] = [
      generateTestFinding({ findingId: asFindingId('empty-in-progress'), remediationStatus: 'IN_PROGRESS' }),
      generateTestFinding({ findingId: asFindingId('empty-success'), remediationStatus: 'SUCCESS' }),
    ];

    it.each<{ scenario: string; findings: FindingApiResponse[]; reportedSelection: FindingApiResponse[] }>([
      {
        scenario: 'the reported selection is empty',
        findings: displayedEligible,
        reportedSelection: [],
      },
      {
        scenario: 'select-all covers only ineligible rows',
        findings: allIneligible,
        reportedSelection: reportEveryDisplayedFinding(allIneligible),
      },
    ])('returns an empty array when $scenario', ({ findings, reportedSelection }) => {
      // GIVEN a displayed list and a reported selection with no eligible members

      // WHEN the reported selection is reduced
      const result = limitFindingSelection(reportedSelection, findings, SELECTION_LIMIT);

      // THEN nothing is stored
      expect(result).toEqual([]);
    });
  });

  describe('reconciles a prior stored selection against a changed displayed list', () => {
    // A prior selection reconciled against a list where its first id is gone —
    // the removed id also stands in for an unknown / stale id not in the list.
    const priorSelectedRemoved = generateTestFinding({
      findingId: asFindingId('recon-a'),
      remediationStatus: 'NOT_STARTED',
    });
    const priorSelectedKept = generateTestFinding({
      findingId: asFindingId('recon-b'),
      remediationStatus: 'NOT_STARTED',
    });
    const displayedAfterRemoval = generateTestFinding({
      findingId: asFindingId('recon-c'),
      remediationStatus: 'NOT_STARTED',
    });

    // The same prior id still present but flipped to an ineligible status.
    const priorNowInProgress = generateTestFinding({
      findingId: asFindingId('recon-a'),
      remediationStatus: 'IN_PROGRESS',
    });
    const priorStillEligible = generateTestFinding({
      findingId: asFindingId('recon-b'),
      remediationStatus: 'NOT_STARTED',
    });

    // An append-only superset that still contains every prior-selected finding.
    const appendedFinding = generateTestFinding({
      findingId: asFindingId('recon-d'),
      remediationStatus: 'NOT_STARTED',
    });

    // A prior selection larger than the cap.
    const overCapPriorSelection = buildEligibleFindings(OVER_LIMIT_COUNT, 'recon-over');

    it('drops a prior-selected finding that is no longer displayed', () => {
      // GIVEN a prior selection whose first finding is absent from the new list
      const priorSelection = [priorSelectedRemoved, priorSelectedKept];
      const changedFindings = [priorSelectedKept, displayedAfterRemoval];

      // WHEN the selection is reconciled against the new displayed list
      const result = limitFindingSelection(priorSelection, changedFindings, SELECTION_LIMIT);

      // THEN the absent finding is dropped and the still-displayed finding is kept
      expect(result).toEqual([priorSelectedKept]);
    });

    it('drops a prior-selected finding that has become ineligible', () => {
      // GIVEN a prior selection whose first finding is now IN_PROGRESS in the new list
      const priorSelection = [priorSelectedRemoved, priorSelectedKept];
      const changedFindings = [priorNowInProgress, priorStillEligible];

      // WHEN the selection is reconciled
      const result = limitFindingSelection(priorSelection, changedFindings, SELECTION_LIMIT);

      // THEN the newly-ineligible finding is dropped and the eligible one is kept
      expect(result).toEqual([priorStillEligible]);
    });

    it('keeps an under-cap selection unchanged when the list only grows', () => {
      // GIVEN a prior under-cap selection and an append-only superset that still contains it
      const priorSelection = [priorSelectedRemoved, priorSelectedKept];
      const appendedList = [priorSelectedRemoved, priorSelectedKept, displayedAfterRemoval, appendedFinding];

      // WHEN the selection is reconciled against the grown list
      const result = limitFindingSelection(priorSelection, appendedList, SELECTION_LIMIT);

      // THEN the prior selection is returned unchanged
      expect(result).toEqual([priorSelectedRemoved, priorSelectedKept]);
    });

    it('re-slices an over-cap prior selection to the cap in display order', () => {
      // GIVEN a prior selection larger than the cap against a matching displayed list

      // WHEN the selection is reconciled
      const result = limitFindingSelection(overCapPriorSelection, overCapPriorSelection, SELECTION_LIMIT);

      // THEN it is re-sliced to the first cap findings in display order
      expect(result).toEqual(overCapPriorSelection.slice(0, SELECTION_LIMIT));
      expect(result.length).toBe(SELECTION_LIMIT);
    });
  });
});
