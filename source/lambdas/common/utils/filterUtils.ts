// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ListParentsCommand, OrganizationsClient, ChildNotFoundException } from '@aws-sdk/client-organizations';
import { Logger } from '@aws-lambda-powertools/logger';
import { ASFFFinding } from '@asr/data-models';
import { ASRParameters } from './constants';
import { getCachedParametersByPath, clearSSMCache } from './ssmCache';

const organizationsClient = new OrganizationsClient({
  maxAttempts: 15,
  retryMode: 'standard',
});

const parentOUCache = new Map<string, string[]>();

export interface FilterConfig {
  accountFilters: string[];
  accountFilterMode: 'Include' | 'Exclude' | 'Disabled';
  ouFilters: string[];
  ouFilterMode: 'Include' | 'Exclude' | 'Disabled';
  tagFilters: string[];
  tagFilterMode: 'Include' | 'Exclude' | 'Disabled';
}

function parseCommaSeparatedValues(value: string): string[] {
  if (value === 'none' || !value) {
    return [];
  }

  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item);
}

function isValidFilterMode(value: string): value is 'Include' | 'Exclude' | 'Disabled' {
  return ['Include', 'Exclude', 'Disabled'].includes(value);
}

function createDefaultFilterConfig(): FilterConfig {
  return {
    accountFilters: [],
    accountFilterMode: 'Disabled',
    ouFilters: [],
    ouFilterMode: 'Disabled',
    tagFilters: [],
    tagFilterMode: 'Disabled',
  };
}

type ParameterProcessor = (config: FilterConfig, value: string) => void;

const parameterProcessors: Record<string, ParameterProcessor> = {
  [ASRParameters.ACCOUNT_FILTERS]: (config, value) => {
    config.accountFilters = parseCommaSeparatedValues(value);
  },
  [ASRParameters.ACCOUNT_FILTER_MODE]: (config, value) => {
    if (isValidFilterMode(value)) {
      config.accountFilterMode = value;
    }
  },
  [ASRParameters.OU_FILTERS]: (config, value) => {
    config.ouFilters = parseCommaSeparatedValues(value);
  },
  [ASRParameters.OU_FILTER_MODE]: (config, value) => {
    if (isValidFilterMode(value)) {
      config.ouFilterMode = value;
    }
  },
  [ASRParameters.TAG_FILTERS]: (config, value) => {
    config.tagFilters = parseCommaSeparatedValues(value);
  },
  [ASRParameters.TAG_FILTER_MODE]: (config, value) => {
    if (isValidFilterMode(value)) {
      config.tagFilterMode = value;
    }
  },
};

function processParameter(config: FilterConfig, paramName: string, paramValue: string): void {
  const processor = parameterProcessors[paramName];
  if (processor) {
    processor(config, paramValue);
  }
}

export async function getFilterConfigurations(logger: Logger): Promise<FilterConfig> {
  const parameters = await getCachedParametersByPath(ASRParameters.FILTERS_PREFIX, logger, true);

  const filterConfig = createDefaultFilterConfig();

  if (parameters) {
    for (const param of parameters) {
      if (param.Name && param.Value) {
        processParameter(filterConfig, param.Name, param.Value);
      }
    }
  }

  logger.debug('Retrieved filter configurations', { filterConfig });
  return filterConfig;
}

export function clearFilterConfigCache(): void {
  clearSSMCache();
  parentOUCache.clear();
}

function isFilterDisabled(filterMode: 'Include' | 'Exclude' | 'Disabled', filterList: string[]): boolean {
  if (filterMode === 'Disabled') {
    return true;
  }
  return filterList.length === 0;
}

function applyGenericFilter(
  values: string[],
  filterList: string[],
  filterMode: 'Include' | 'Exclude' | 'Disabled',
  filterName: string,
  logger: Logger,
  logContext: Record<string, any>,
): boolean {
  const matchingValues = values.filter((value) => filterList.includes(value));
  const isInFilterList = matchingValues.length > 0;

  const passes = filterMode === 'Include' ? isInFilterList : !isInFilterList;

  logger.debug(`${filterName} filter (${filterMode} mode): ${passes ? 'PASSED' : 'FAILED'}`, {
    ...logContext,
    filterList,
    matchingValues,
  });

  return passes;
}

export async function applyAccountFilter(
  finding: ASFFFinding,
  filterConfig: FilterConfig,
  logger: Logger,
): Promise<boolean> {
  if (isFilterDisabled(filterConfig.accountFilterMode, filterConfig.accountFilters)) {
    return true;
  }

  return applyGenericFilter(
    [finding.AwsAccountId],
    filterConfig.accountFilters,
    filterConfig.accountFilterMode,
    'Account',
    logger,
    { accountId: finding.AwsAccountId },
  );
}

function getCachedParentOUs(accountId: string, logger: Logger): string[] | null {
  if (parentOUCache.has(accountId)) {
    logger.debug('Using cached parent OUs', { accountId });
    return parentOUCache.get(accountId) as string[];
  }
  return null;
}

function extractParentIds(parents: any[]): string[] {
  const ouIds: string[] = [];
  for (const parent of parents) {
    if (parent.Id) {
      ouIds.push(parent.Id);
    }
  }
  return ouIds;
}

function cacheAndReturnOUs(accountId: string, ouIds: string[], logger: Logger): string[] {
  parentOUCache.set(accountId, ouIds);
  if (ouIds.length > 0) {
    logger.debug('Retrieved and cached account OUs', { accountId, ouIds });
  } else {
    logger.debug('No parent OUs found for account', { accountId });
  }
  return ouIds;
}

function handleOrganizationsError(error: unknown, accountId: string, logger: Logger): string[] {
  if (error instanceof ChildNotFoundException) {
    logger.warn('Account not found in AWS Organizations or is not a child account', {
      accountId,
      errorName: 'ChildNotFoundException',
      message: 'Account may have been removed from organization or never existed',
    });
  } else {
    logger.error('Error retrieving account OUs', {
      accountId,
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : '',
    });
  }

  parentOUCache.set(accountId, []);
  return [];
}

async function getParentOUs(accountId: string, logger: Logger): Promise<string[]> {
  const cachedResult = getCachedParentOUs(accountId, logger);
  if (cachedResult !== null) {
    return cachedResult;
  }

  try {
    const listParentsResponse = await organizationsClient.send(
      new ListParentsCommand({
        ChildId: accountId,
      }),
    );

    if (!listParentsResponse.Parents || listParentsResponse.Parents.length === 0) {
      return cacheAndReturnOUs(accountId, [], logger);
    }

    const ouIds = extractParentIds(listParentsResponse.Parents);
    return cacheAndReturnOUs(accountId, ouIds, logger);
  } catch (error) {
    return handleOrganizationsError(error, accountId, logger);
  }
}

/**
 * @description Applies OU filter logic
 * @param finding Security finding
 * @param filterConfig Filter configuration
 * @param logger Logger instance
 * @returns Boolean indicating if finding passes filter
 */
export async function applyOUFilter(
  finding: ASFFFinding,
  filterConfig: FilterConfig,
  logger: Logger,
): Promise<boolean> {
  if (isFilterDisabled(filterConfig.ouFilterMode, filterConfig.ouFilters)) {
    return true;
  }

  const accountId = finding.AwsAccountId;
  const parentOUs = await getParentOUs(accountId, logger);

  if (parentOUs.length === 0) {
    logger.warn('Could not retrieve OUs for account, skipping OU filtering', { accountId });
    return true;
  }

  return applyGenericFilter(parentOUs, filterConfig.ouFilters, filterConfig.ouFilterMode, 'OU', logger, {
    accountId,
    parentOUs,
  });
}

function extractResourceTagKeys(finding: ASFFFinding, logger: Logger): string[] {
  try {
    const allTagKeys: string[] = [];

    if (finding.Resources) {
      for (const resource of finding.Resources) {
        if (resource.Tags) {
          const tagKeys = Object.keys(resource.Tags);
          allTagKeys.push(...tagKeys);
        }
      }
    }

    const uniqueTagKeys = [...new Set(allTagKeys)];

    logger.debug('Extracted tag keys from finding resources', {
      findingId: finding.Id,
      resourceCount: finding.Resources?.length || 0,
      uniqueTagKeys,
    });

    return uniqueTagKeys;
  } catch (error) {
    logger.error('Error extracting tag keys from finding', {
      findingId: finding.Id,
      error: error instanceof Error ? error.message : String(error),
    });
    return [];
  }
}

export async function applyTagFilter(
  finding: ASFFFinding,
  filterConfig: FilterConfig,
  logger: Logger,
): Promise<boolean> {
  if (isFilterDisabled(filterConfig.tagFilterMode, filterConfig.tagFilters)) {
    return true;
  }

  const resourceTagKeys = extractResourceTagKeys(finding, logger);

  if (resourceTagKeys.length === 0) {
    logger.debug('No tags found on finding resources, skipping tag filtering', {
      findingId: finding.Id,
    });
    return true;
  }

  return applyGenericFilter(resourceTagKeys, filterConfig.tagFilters, filterConfig.tagFilterMode, 'Tag', logger, {
    findingId: finding.Id,
    resourceTagKeys,
  });
}

export interface FilterResult {
  passed: boolean;
  appliedFilter: 'account_id_filter' | 'OUs_filter' | 'tags_filter' | 'none';
}

interface FilterCheck {
  check: () => Promise<boolean>;
  failureResult: FilterResult['appliedFilter'];
  failureMessage: string;
  context: Record<string, any>;
}

function createFilterChecks(finding: ASFFFinding, filterConfig: FilterConfig, logger: Logger): FilterCheck[] {
  return [
    {
      check: () => applyAccountFilter(finding, filterConfig, logger),
      failureResult: 'account_id_filter',
      failureMessage: 'Finding failed account filter check',
      context: { accountId: finding.AwsAccountId, accountFilterMode: filterConfig.accountFilterMode },
    },
    {
      check: () => applyOUFilter(finding, filterConfig, logger),
      failureResult: 'OUs_filter',
      failureMessage: 'Finding failed OU filter check',
      context: { accountId: finding.AwsAccountId, ouFilterMode: filterConfig.ouFilterMode },
    },
    {
      check: () => applyTagFilter(finding, filterConfig, logger),
      failureResult: 'tags_filter',
      failureMessage: 'Finding failed tag filter check',
      context: { resourceArns: finding.Resources.map((r) => r.Id), tagFilterMode: filterConfig.tagFilterMode },
    },
  ];
}

async function executeFilterCheck(
  filterCheck: FilterCheck,
  findingId: string,
  logger: Logger,
): Promise<FilterResult | null> {
  const passes = await filterCheck.check();
  if (!passes) {
    logger.debug(filterCheck.failureMessage, {
      findingId,
      ...filterCheck.context,
    });
    return { passed: false, appliedFilter: filterCheck.failureResult };
  }
  return null;
}

export async function applyFilters(finding: ASFFFinding, logger: Logger): Promise<FilterResult> {
  const filterConfig = await getFilterConfigurations(logger);
  const filterChecks = createFilterChecks(finding, filterConfig, logger);

  for (const filterCheck of filterChecks) {
    const result = await executeFilterCheck(filterCheck, finding.Id, logger);
    if (result) {
      return result;
    }
  }

  logger.debug('Finding passed all filter checks', { findingId: finding.Id });
  return { passed: true, appliedFilter: 'none' };
}
