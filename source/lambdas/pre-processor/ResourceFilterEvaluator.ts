// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ListParentsCommand, OrganizationsClient, ChildNotFoundException } from '@aws-sdk/client-organizations';
import { Logger } from '@aws-lambda-powertools/logger';
import { FilterMode, ResourceFilterDynamoDBItem, TagPair, NormalizedFinding } from '@asr/data-models';
import { Clock, getClock } from '../common/utils/clock';
import { FiltersRepository } from '../common/repositories/filtersRepository';
import { arnMatchesPattern } from '../common/utils/wildcardMatch';

export interface ResourceFilterEvaluationResult {
  passed: boolean;
  reason: string;
}

/**
 * Optional per-caller cache of filter-definition lookups, keyed by the requested filter-id set. A
 * `batchFindByIds` result depends only on the filter IDs (not on the finding being evaluated), so a
 * caller that evaluates many findings against the same filter set — for example reconciliation
 * walking a control's findings — can supply this cache to fetch each definition set from DynamoDB
 * once instead of once per finding. When omitted, every call fetches fresh, preserving the original
 * behavior for callers that evaluate a single finding per invocation.
 */
export type FilterDefinitionCache = Map<string, ResourceFilterDynamoDBItem[]>;

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CACHE_MAX_SIZE = 1000; // Maximum number of accounts to cache

export interface ParentOUCache {
  get(accountId: string): string[] | undefined;
  set(accountId: string, ouIds: string[]): void;
  clear(): void;
  size: number;
}

class DefaultParentOUCache implements ParentOUCache {
  private readonly cache = new Map<string, string[]>();
  private cacheCreatedAt = 0;

  constructor(private readonly clock: Clock) {}

  get(accountId: string): string[] | undefined {
    this.clearIfExpired();
    return this.cache.get(accountId);
  }

  set(accountId: string, ouIds: string[]): void {
    this.clearIfExpired();
    this.cache.set(accountId, ouIds);
  }

  clear(): void {
    this.cache.clear();
    this.cacheCreatedAt = this.clock.now().getTime();
  }

  get size(): number {
    return this.cache.size;
  }

  private clearIfExpired(): void {
    const now = this.clock.now().getTime();
    if (now - this.cacheCreatedAt > CACHE_TTL_MS || this.cache.size >= CACHE_MAX_SIZE) {
      this.cache.clear();
      this.cacheCreatedAt = now;
    }
  }
}

export class ResourceFilterEvaluator {
  private readonly parentOUCache: ParentOUCache;

  constructor(
    private readonly filtersRepository: FiltersRepository,
    private readonly logger: Logger,
    private readonly organizationsClient: OrganizationsClient = new OrganizationsClient({
      maxAttempts: 15,
      retryMode: 'standard',
    }),
    clock: Clock = getClock(),
    parentOUCache?: ParentOUCache,
  ) {
    this.parentOUCache = parentOUCache ?? new DefaultParentOUCache(clock);
  }

  async evaluateFilters(
    finding: NormalizedFinding,
    filterIds: string[],
    filterMode: FilterMode,
    filterDefinitionCache?: FilterDefinitionCache,
  ): Promise<ResourceFilterEvaluationResult> {
    if (filterIds.length === 0) {
      this.logger.debug('No filters configured for control, allowing remediation', { findingId: finding.id });
      return { passed: true, reason: 'no_filters_configured' };
    }

    const filters = await this.batchFindFilters(filterIds, filterDefinitionCache);
    if (filters.length === 0) {
      this.logger.error('No valid filters found for configured filter IDs, blocking remediation as fail-safe', {
        findingId: finding.id,
        filterIds,
      });
      return { passed: false, reason: 'no_valid_filters_found' };
    }

    // Fail closed unless every configured filter resolved to a record. A configured filter that no
    // longer exists in DynamoDB is silently omitted by BatchGetItem (absent from `filters`), so the
    // complete set of constraints cannot be confirmed and remediation must not proceed on a partial view.
    const resolvedFilterIds = new Set(filters.map((filter) => filter.filterId));
    const allFiltersResolved = filterIds.every((filterId) => resolvedFilterIds.has(filterId));

    if (!allFiltersResolved && filterMode === 'exclude') {
      this.logger.error(
        'Incomplete filter retrieval in exclude mode, blocking remediation to prevent bypassing exclusion filters',
        { findingId: finding.id, retrievedCount: filters.length, requestedCount: filterIds.length },
      );
      return { passed: false, reason: 'incomplete_filter_retrieval_in_exclude_mode' };
    }

    if (!allFiltersResolved && filterMode === 'include') {
      this.logger.error(
        'Incomplete filter retrieval in include mode, blocking remediation because unverified filters cannot be confirmed as matching',
        { findingId: finding.id, retrievedCount: filters.length, requestedCount: filterIds.length },
      );
      return { passed: false, reason: 'incomplete_filter_retrieval_in_include_mode' };
    }

    if (filterMode === 'include') {
      return this.evaluateIncludeMode(finding, filters);
    } else {
      return this.evaluateExcludeMode(finding, filters);
    }
  }

  /**
   * Fetches the filter definitions for `filterIds`, consulting `cache` when provided. The cache key
   * is the filter-id set (order-independent), and the cached value is the unmodified
   * `batchFindByIds` result — which is a pure function of the filter IDs — so a hit is equivalent to
   * a fresh fetch. With no cache, this is a direct passthrough to the repository.
   */
  private async batchFindFilters(
    filterIds: string[],
    cache?: FilterDefinitionCache,
  ): Promise<ResourceFilterDynamoDBItem[]> {
    if (!cache) {
      return this.filtersRepository.batchFindByIds(filterIds);
    }

    const cacheKey = [...filterIds].sort((a, b) => a.localeCompare(b)).join('\u0000');
    const cached = cache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const result = await this.filtersRepository.batchFindByIds(filterIds);
    cache.set(cacheKey, result);
    return result;
  }

  private async evaluateIncludeMode(
    finding: NormalizedFinding,
    filters: ResourceFilterDynamoDBItem[],
  ): Promise<ResourceFilterEvaluationResult> {
    for (const filter of filters) {
      const isMatch = await this.doesFilterMatch(finding, filter);
      if (!isMatch) {
        this.logger.debug('Finding does not match filter in include mode, blocking remediation', {
          findingId: finding.id,
          filterId: filter.filterId,
          filterName: filter.name,
        });
        return { passed: false, reason: `filter_not_matched:${filter.filterId}` };
      }
    }

    this.logger.debug('Finding matches all filters in include mode, allowing remediation', {
      findingId: finding.id,
      filterCount: filters.length,
    });
    return { passed: true, reason: 'all_filters_matched' };
  }

  private async evaluateExcludeMode(
    finding: NormalizedFinding,
    filters: ResourceFilterDynamoDBItem[],
  ): Promise<ResourceFilterEvaluationResult> {
    for (const filter of filters) {
      const isMatch = await this.doesFilterMatch(finding, filter);
      if (isMatch) {
        this.logger.debug('Finding matches filter in exclude mode, blocking remediation', {
          findingId: finding.id,
          filterId: filter.filterId,
          filterName: filter.name,
        });
        return { passed: false, reason: `filter_matched_exclusion:${filter.filterId}` };
      }
    }

    this.logger.debug('Finding does not match any filters in exclude mode, allowing remediation', {
      findingId: finding.id,
      filterCount: filters.length,
    });
    return { passed: true, reason: 'no_exclusion_filters_matched' };
  }

  private async doesFilterMatch(finding: NormalizedFinding, filter: ResourceFilterDynamoDBItem): Promise<boolean> {
    const accountIds = this.normalizeStringSet(filter.accountIds);
    const organizationalUnits = this.normalizeStringSet(filter.organizationalUnits);
    const arnPatterns = this.normalizeStringSet(filter.arnPatterns);
    const tags = filter.tags || [];

    const hasAccountCriteria = accountIds.length > 0;
    const hasOUCriteria = organizationalUnits.length > 0;
    const hasTagCriteria = tags.length > 0;
    const hasArnCriteria = arnPatterns.length > 0;

    if (!hasAccountCriteria && !hasOUCriteria && !hasTagCriteria && !hasArnCriteria) {
      this.logger.debug('Filter has no criteria, treating as match', { filterId: filter.filterId });
      return true;
    }

    const results: boolean[] = [];

    if (hasAccountCriteria) {
      results.push(this.matchesAccountId(finding.accountId, accountIds));
    }

    if (hasOUCriteria) {
      const ouMatch = await this.matchesOrganizationalUnit(finding.accountId, organizationalUnits);
      results.push(ouMatch);
    }

    if (hasTagCriteria) {
      const tagMatch = this.matchesTags(finding, tags);
      if (tagMatch !== null) {
        results.push(tagMatch);
      }
    }

    if (hasArnCriteria) {
      results.push(this.matchesArnPatterns(finding, arnPatterns));
    }

    if (results.length === 0) {
      this.logger.debug(
        'Filter has no applicable criteria for this resource (e.g., tag-only filter on non-taggable resource), treating as non-match',
        { filterId: filter.filterId },
      );
      return false;
    }

    return results.every(Boolean);
  }

  private normalizeStringSet(value: Set<string> | string[] | undefined): string[] {
    if (!value) return [];
    return value instanceof Set ? Array.from(value) : value;
  }

  private matchesAccountId(findingAccountId: string, filterAccountIds: string[]): boolean {
    return filterAccountIds.includes(findingAccountId);
  }

  private async matchesOrganizationalUnit(accountId: string, filterOUs: string[]): Promise<boolean> {
    const parentOUs = await this.getParentOUs(accountId);
    return parentOUs.some((ou) => filterOUs.includes(ou));
  }

  private async getParentOUs(accountId: string): Promise<string[]> {
    const MAX_OU_DEPTH = 20;
    const cached = this.parentOUCache.get(accountId);
    if (cached) {
      return cached;
    }

    const ouIds: string[] = [];
    let childId = accountId;

    try {
      for (let depth = 0; depth < MAX_OU_DEPTH; depth++) {
        const response = await this.organizationsClient.send(new ListParentsCommand({ ChildId: childId }));
        const parent = (response.Parents || [])[0];
        if (!parent?.Id || parent.Type === 'ROOT') break;
        ouIds.push(parent.Id);
        childId = parent.Id;
      }
      if (ouIds.length >= MAX_OU_DEPTH) {
        this.logger.warn('OU hierarchy traversal reached maximum depth', { accountId, maxDepth: MAX_OU_DEPTH });
      }
      this.parentOUCache.set(accountId, ouIds);
      return ouIds;
    } catch (error) {
      if (error instanceof ChildNotFoundException) {
        this.logger.warn('Account not found in AWS Organizations', { accountId });
        this.parentOUCache.set(accountId, []);
        return [];
      }
      this.logger.error('Transient error retrieving account OUs, treating as no OU match', { accountId, error });
      return [];
    }
  }

  private matchesTags(finding: NormalizedFinding, filterTags: TagPair[]): boolean | null {
    const resourceTags = this.extractResourceTags(finding);

    if (resourceTags === null) {
      this.logger.debug('Resource does not support tagging, ignoring tag filter criteria', {
        findingId: finding.id,
      });
      return null;
    }

    if (Object.keys(resourceTags).length === 0) {
      return false;
    }

    return filterTags.every((filterTag) => resourceTags[filterTag.key] === filterTag.value);
  }

  private extractResourceTags(finding: NormalizedFinding): Record<string, string> | null {
    if (!finding.resources || finding.resources.length === 0) {
      return null;
    }

    const primaryResource = finding.resources[0];
    if (!primaryResource.tags) {
      return {};
    }

    const tags: Record<string, string> = {};
    for (const [key, value] of Object.entries(primaryResource.tags)) {
      if (value !== undefined) {
        tags[key] = value;
      }
    }
    return tags;
  }

  private matchesArnPatterns(finding: NormalizedFinding, arnPatterns: string[]): boolean {
    if (!finding.resources || finding.resources.length === 0) {
      return false;
    }

    const resourceArn = finding.resources[0].id;
    return arnPatterns.some((pattern) => arnMatchesPattern(resourceArn, pattern));
  }
}
