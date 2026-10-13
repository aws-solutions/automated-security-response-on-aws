// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it } from 'vitest';
import { controlsTablePreferences } from '../../utils/tablePreferences';

describe('controlsTablePreferences', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns the full default column set for a first-time user', () => {
    // The defaults are the single source of truth for which columns exist; a fresh visitor
    // with no stored preferences must see all of them, including source and rollbackEnabled.
    const visible = controlsTablePreferences.load().visibleContent;

    expect(visible).toContain('source');
    expect(visible).toContain('rollbackEnabled');
  });

  it('lets stored preferences override the defaults once they are on the current version', () => {
    // A returning user's own column choices win over the defaults, so hiding a column stays
    // hidden on the next load, while fields the user never set fall back to the defaults.
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({ pageSize: 50, visibleContent: ['controlId', 'isEnabled'], preferencesVersion: 3 }),
    );

    const loaded = controlsTablePreferences.load();

    expect(loaded.visibleContent).toEqual(['controlId', 'isEnabled']);
    expect(loaded.pageSize).toBe(50);
    // contentDensity was not stored, so it comes from the defaults.
    expect(loaded.contentDensity).toBe('comfortable');
  });

  it('adds the columns introduced since the first release to a returning user, keeping their hidden ones hidden', () => {
    // The first release shipped this table without source, rollbackEnabled, or runbookVersion
    // and without a version, so an upgrading user's stored columns would otherwise replace the
    // defaults and hide the new columns permanently — which would make them unreachable for
    // every existing user, the one audience this change is for.
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({
        visibleContent: ['controlId', 'description', 'isEnabled', 'appliedFilters', 'modifiedBy'],
      }),
    );

    const loaded = controlsTablePreferences.load();

    expect(loaded.visibleContent).toEqual([
      'controlId',
      'description',
      'isEnabled',
      'appliedFilters',
      'modifiedBy',
      'rollbackEnabled',
      'source',
      'runbookVersion',
    ]);
    // notifications and lastModified were not stored, so they stay hidden: only the newly
    // introduced columns are unioned in, never every default.
    expect(loaded.visibleContent).not.toContain('notifications');
    expect(loaded.visibleContent).not.toContain('lastModified');
  });

  it('adds only the newest columns to preferences already carrying rollbackEnabled', () => {
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({ visibleContent: ['controlId', 'rollbackEnabled'], preferencesVersion: 1 }),
    );

    // A v1 user migrating to v3 gets what v2 (source) and v3 (runbookVersion) introduced.
    expect(controlsTablePreferences.load().visibleContent).toEqual([
      'controlId',
      'rollbackEnabled',
      'source',
      'runbookVersion',
    ]);
  });

  it('adds only runbookVersion when migrating a stored version-2 user to version 3', () => {
    // The 2 -> 3 migration in isolation: a user already carrying source (v2) but not
    // runbookVersion gains only runbookVersion, and their hidden columns stay hidden.
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({ visibleContent: ['controlId', 'source'], preferencesVersion: 2 }),
    );

    const loaded = controlsTablePreferences.load();

    expect(loaded.visibleContent).toEqual(['controlId', 'source', 'runbookVersion']);
    expect(loaded.visibleContent).not.toContain('rollbackEnabled');
    expect(loaded.preferencesVersion).toBe(3);
  });

  it('does not re-add a column the user hid at a version they already have', () => {
    // A v1 user who deliberately hid rollbackEnabled. Migrating 1 → 3 must add only what v2 and
    // v3 introduced: a cumulative "added since 0" list would union rollbackEnabled back in and
    // silently overrule them, which is the whole reason the columns are keyed by version.
    localStorage.setItem(
      'controlsTablePreferences',
      JSON.stringify({ visibleContent: ['controlId', 'isEnabled'], preferencesVersion: 1 }),
    );

    const loaded = controlsTablePreferences.load();

    expect(loaded.visibleContent).toEqual(['controlId', 'isEnabled', 'source', 'runbookVersion']);
    expect(loaded.visibleContent).not.toContain('rollbackEnabled');
    expect(loaded.preferencesVersion).toBe(3);
  });

  it('records the current version when saving, so the migration runs once', () => {
    localStorage.setItem('controlsTablePreferences', JSON.stringify({ visibleContent: ['controlId'] }));

    controlsTablePreferences.save({ pageSize: 30 });
    // The user now hides source deliberately; it must not come back on the next load.
    controlsTablePreferences.save({ visibleContent: ['controlId', 'rollbackEnabled'] });

    expect(controlsTablePreferences.load().visibleContent).toEqual(['controlId', 'rollbackEnabled']);
  });

  it('falls back to the defaults when stored preferences are malformed', () => {
    localStorage.setItem('controlsTablePreferences', 'not json');

    expect(controlsTablePreferences.load().visibleContent).toContain('source');
  });

  it('persists a partial update merged over the current preferences', () => {
    controlsTablePreferences.save({ pageSize: 40 });

    const loaded = controlsTablePreferences.load();

    expect(loaded.pageSize).toBe(40);
    // Unmodified fields are preserved from the defaults.
    expect(loaded.visibleContent).toContain('source');
  });
});
