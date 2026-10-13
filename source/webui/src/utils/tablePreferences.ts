// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PropertyFilterProps } from '@cloudscape-design/components/property-filter';

interface BaseTablePreferences {
  sortingField: string;
  sortingDescending: boolean;
  filterTokens: PropertyFilterProps.Token[];
  preferencesVersion?: number;
}

interface FindingsTablePreferences extends BaseTablePreferences {
  showSuppressed: boolean;
  visibleContent?: string[];
}

interface ControlsTablePreferences {
  pageSize: number;
  visibleContent: string[];
  contentDensity: 'compact' | 'comfortable';
  preferencesVersion?: number;
}

type TablePreferences = BaseTablePreferences | FindingsTablePreferences | ControlsTablePreferences;

interface PreferencesManager<T extends TablePreferences> {
  load(): T;
  save(preferences: Partial<T>): void;
}

interface WithVisibleContent {
  visibleContent: string[];
}

function hasVisibleContent<T>(preferences: T): preferences is T & WithVisibleContent {
  return (
    typeof preferences === 'object' &&
    preferences !== null &&
    'visibleContent' in preferences &&
    Array.isArray((preferences as { visibleContent?: unknown }).visibleContent)
  );
}

/**
 * Columns introduced by each version bump, keyed by the version that introduced them.
 *
 * Per-version rather than one cumulative list. A cumulative "columns added since 0" list
 * re-adds every column on any upgrade, so a user already at version 1 — who by definition had
 * seen the column version 1 introduced and may have deliberately hidden it — would have it
 * unioned back in on the way to 2. Keyed this way, a 1 → 2 migration adds only what 2 added.
 */
type ColumnsAddedByVersion = Readonly<Record<number, readonly string[]>>;

/**
 * @param defaultsVersion version of the current default column set, bumped whenever a column
 *   is added to `defaults.visibleContent`
 * @param columnsAddedByVersion the columns each version bump introduced; only those from
 *   versions newer than the user's are unioned into their stored `visibleContent`
 *
 * Stored `visibleContent` replaces the default array wholesale — object spread does not merge
 * arrays — so adding a column to the defaults alone leaves every upgrading user unable to see
 * it. v4.0.0 shipped the Controls table, so those preferences exist in the wild and carry no
 * `preferencesVersion` and are treated as version 0. Only columns from versions the user has
 * not yet seen are added, which is what keeps a column they deliberately hid hidden.
 */
function createPreferencesManager<T extends TablePreferences>(
  storageKey: string,
  defaults: T,
  defaultsVersion: number,
  columnsAddedByVersion: ColumnsAddedByVersion = {},
): PreferencesManager<T> {
  return {
    load(): T {
      try {
        const stored = localStorage.getItem(storageKey);
        if (!stored) return defaults;
        const parsed: unknown = JSON.parse(stored);
        if (typeof parsed !== 'object' || parsed === null) return defaults;
        const storedPreferences: T = { ...defaults, ...parsed };
        if (!hasVisibleContent(storedPreferences) || !hasVisibleContent(defaults)) return storedPreferences;

        const storedVersion = storedPreferences.preferencesVersion ?? 0;
        if (storedVersion >= defaultsVersion) return storedPreferences;

        const storedVisible = storedPreferences.visibleContent;
        const columnsToAdd = Object.entries(columnsAddedByVersion)
          .filter(([version]) => Number(version) > storedVersion)
          .flatMap(([, columns]) => columns)
          .filter((columnId) => !storedVisible.includes(columnId));
        return {
          ...storedPreferences,
          visibleContent: [...storedVisible, ...columnsToAdd],
          preferencesVersion: defaultsVersion,
        };
      } catch {
        return defaults;
      }
    },

    save(preferences: Partial<T>): void {
      try {
        const current = this.load();
        localStorage.setItem(
          storageKey,
          JSON.stringify({ ...current, ...preferences, preferencesVersion: defaultsVersion }),
        );
      } catch {
        console.log('Unable to save table preferences');
        // Silently fail if storage is unavailable
      }
    },
  };
}

export const findingsTablePreferences = createPreferencesManager<FindingsTablePreferences>(
  'findingsTablePreferences',
  {
    sortingField: 'securityHubUpdatedAtTime',
    sortingDescending: true,
    filterTokens: [],
    showSuppressed: false,
  },
  1,
);

export const historyTablePreferences = createPreferencesManager<BaseTablePreferences>(
  'historyTablePreferences',
  {
    sortingField: 'lastUpdatedTime',
    sortingDescending: true,
    filterTokens: [],
  },
  1,
);

export const controlsTablePreferences = createPreferencesManager<ControlsTablePreferences>(
  'controlsTablePreferences',
  {
    pageSize: 20,
    visibleContent: [
      'controlId',
      'description',
      'isEnabled',
      'source',
      'runbookVersion',
      'rollbackEnabled',
      'appliedFilters',
      'notifications',
      'modifiedBy',
      'lastModified',
    ],
    contentDensity: 'comfortable',
  },
  3,
  // v1 added the rollback column; v2 added the custom-runbook source column; v3 split the
  // runbook version into its own column.
  { 1: ['rollbackEnabled'], 2: ['source'], 3: ['runbookVersion'] },
);
