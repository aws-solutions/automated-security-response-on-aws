// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { PropertyFilterProps } from '@cloudscape-design/components/property-filter';

interface BaseTablePreferences {
  sortingField: string;
  sortingDescending: boolean;
  filterTokens: PropertyFilterProps.Token[];
}

interface FindingsTablePreferences extends BaseTablePreferences {
  showSuppressed: boolean;
  visibleContent?: string[];
}

interface ControlsTablePreferences {
  pageSize: number;
  visibleContent: string[];
  contentDensity: 'compact' | 'comfortable';
}

type TablePreferences = BaseTablePreferences | FindingsTablePreferences | ControlsTablePreferences;

function createPreferencesManager<T extends TablePreferences>(storageKey: string, defaults: T) {
  return {
    load(): T {
      try {
        const stored = localStorage.getItem(storageKey);
        return stored ? JSON.parse(stored) : defaults;
      } catch {
        return defaults;
      }
    },

    save(preferences: Partial<T>): void {
      try {
        const current = this.load();
        localStorage.setItem(storageKey, JSON.stringify({ ...current, ...preferences }));
      } catch {
        console.log('Unable to save table preferences');
        // Silently fail if storage is unavailable
      }
    },
  };
}

export const findingsTablePreferences = createPreferencesManager<FindingsTablePreferences>('findingsTablePreferences', {
  sortingField: 'securityHubUpdatedAtTime',
  sortingDescending: true,
  filterTokens: [],
  showSuppressed: false,
});

export const historyTablePreferences = createPreferencesManager<BaseTablePreferences>('historyTablePreferences', {
  sortingField: 'lastUpdatedTime',
  sortingDescending: true,
  filterTokens: [],
});

export const controlsTablePreferences = createPreferencesManager<ControlsTablePreferences>('controlsTablePreferences', {
  pageSize: 20,
  visibleContent: [
    'controlId',
    'description',
    'isEnabled',
    'appliedFilters',
    'notifications',
    'modifiedBy',
    'lastModified',
  ],
  contentDensity: 'comfortable',
});
