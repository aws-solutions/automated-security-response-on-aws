// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { SearchCriteria, SearchFilter, FindingAbstractData } from '@asr/data-models';
import { AuthenticatedUser } from './authorization';
import { DEFAULT_PAGE_SIZE } from '../../common/constants/apiConstant';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { BadRequestError } from '../../common/utils/httpErrors';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { normalizeResourceType } from '../../common/services/findingDataService';

type ResourceType = 'Findings' | 'Remediations';

interface StringFilter {
  FieldName?: string;
  Filter?: {
    Value?: string;
    Comparison?: 'CONTAINS' | 'NOT_CONTAINS' | 'EQUALS' | 'NOT_EQUALS' | 'GREATER_THAN_OR_EQUAL' | 'LESS_THAN_OR_EQUAL';
  };
}

interface CompositeFilter {
  Operator: 'AND' | 'OR';
  StringFilters: StringFilter[];
}

interface SearchRequest {
  Filters?: {
    StringFilters?: StringFilter[];
    CompositeFilters?: CompositeFilter[];
    CompositeOperator?: 'AND' | 'OR';
  };
  SortCriteria?: Array<{
    Field: string;
    SortOrder: 'asc' | 'desc';
  }>;
  NextToken?: string;
}

// Searches for Resource Type use resourceTypeNormalized instead of resourceType since the value of resourceType is inconsistent
const RESOURCE_TYPE_SEARCH_FIELD: keyof FindingAbstractData = 'resourceTypeNormalized';

// Attributes shared by both stores, hence filterable on either search.
const COMMON_FILTER_FIELDS = [
  'findingType',
  'findingId',
  'accountId',
  'resourceId',
  'resourceType',
  'resourceTypeNormalized',
  'severity',
  'region',
  'remediationStatus',
  'lastUpdatedTime',
  'executionId',
  'error',
] as const;

/**
 * The attribute names each search accepts in a `StringFilters` entry.
 *
 * An unsupported name used to reach DynamoDB verbatim as a FilterExpression over an
 * attribute no item has, and what happened next depended on the comparison. `EQUALS`
 * and `CONTAINS` matched nothing, so the caller got an empty page and HTTP 200 —
 * indistinguishable from "no matching records". `NOT_CONTAINS` became
 * `NOT contains(#Typo, :value)`, and since `contains` is false for an attribute that
 * does not exist, it was true for every item: the filter silently vanished and the
 * caller got a wider answer than they asked for. Rejecting the name makes the mistake
 * legible and stops the two shapes from disagreeing. The unresolvable name also
 * disqualified the query from index selection, so it paid for an unfiltered walk.
 *
 * This is a correctness and cost fix, not an authorization one: account scope is
 * composed server-side in `applyAccountFilteringForAccountOperators` and ANDed in as
 * its own field group, which an unknown field name cannot widen.
 *
 * Kept to stored, filterable scalars: composite sort keys, the binary `findingJSON`
 * and internal bookkeeping attributes are deliberately absent.
 */
const SEARCHABLE_FILTER_FIELDS: Record<ResourceType, ReadonlySet<string>> = {
  Findings: new Set<string>([
    ...COMMON_FILTER_FIELDS,
    'findingDescription',
    'securityHubUpdatedAtTime',
    'suppressed',
    'creationTime',
  ]),
  Remediations: new Set<string>([
    ...COMMON_FILTER_FIELDS,
    'lastUpdatedBy',
    'ssmExecutionId',
    'snapshotVersionId',
    'remediationConfigTableKey',
  ]),
};

export abstract class BaseSearchService {
  protected readonly dynamoDBClient: DynamoDBDocumentClient;

  protected constructor(protected readonly logger: Logger) {
    this.dynamoDBClient = createDynamoDBClient({ maxAttempts: 10 });
  }

  /**
   * Validates and converts a string filter to SearchFilter format
   * @param stringFilter - The string filter to validate and convert
   * @returns SearchFilter object if valid, null if invalid
   */
  private validateAndConvertStringFilter(stringFilter: StringFilter): SearchFilter | null {
    if (
      !stringFilter.FieldName ||
      !stringFilter.Filter ||
      !stringFilter.Filter.Value ||
      !stringFilter.Filter.Comparison
    ) {
      return null;
    }

    let fieldName = stringFilter.FieldName;
    let normalizedValue = stringFilter.Filter.Value;

    // ResourceType is a special case since the format varies between Security Hub & Security Hub CSPM
    if (stringFilter.FieldName.toLowerCase() === 'resourcetype') {
      normalizedValue = normalizeResourceType(stringFilter.Filter.Value);
      fieldName = RESOURCE_TYPE_SEARCH_FIELD;
    }

    return {
      fieldName: fieldName,
      value: normalizedValue,
      comparison: stringFilter.Filter.Comparison,
    };
  }

  /**
   * Processes string filters and adds valid ones to the filters array
   * @param stringFilters - Array of string filters to process
   * @param filters - Target array to add valid filters to
   */
  private processStringFilters(stringFilters: StringFilter[], filters: SearchFilter[]): void {
    for (const stringFilter of stringFilters) {
      const convertedFilter = this.validateAndConvertStringFilter(stringFilter);
      if (convertedFilter) {
        filters.push(convertedFilter);
      }
    }
  }

  /**
   * Rejects the request if it filters on a field the given search does not support.
   *
   * See {@link SEARCHABLE_FILTER_FIELDS} for why an unsupported name must not be
   * passed through. A filter with no `FieldName` at all is left to the existing
   * conversion, which drops it: the WebUI emits one for a token that carries no
   * property key, and failing that request would be a regression.
   */
  private assertSupportedFilterFields(request: SearchRequest, resourceType: ResourceType): void {
    const supportedFields = SEARCHABLE_FILTER_FIELDS[resourceType];
    const stringFilters = [
      ...(request.Filters?.StringFilters ?? []),
      ...(request.Filters?.CompositeFilters ?? []).flatMap((compositeFilter) => compositeFilter.StringFilters ?? []),
    ];

    const unsupportedFields = stringFilters
      .map((stringFilter) => stringFilter.FieldName)
      .filter((fieldName): fieldName is string => !!fieldName)
      // ResourceType is accepted in any casing, matching validateAndConvertStringFilter.
      .filter((fieldName) => fieldName.toLowerCase() !== 'resourcetype')
      .filter((fieldName) => !supportedFields.has(fieldName));

    if (unsupportedFields.length > 0) {
      const supportedFieldList = [...supportedFields].sort((a, b) => a.localeCompare(b)).join(', ');
      throw new BadRequestError(
        `Unsupported filter field(s) for ${resourceType}: ${[...new Set(unsupportedFields)]
          .sort((a, b) => a.localeCompare(b))
          .join(', ')}. ` + `Supported fields: ${supportedFieldList}.`,
      );
    }
  }

  /**
   * Processes composite filters and adds valid string filters to the filters array
   * @param compositeFilters - Array of composite filters to process
   * @param filters - Target array to add valid filters to
   */
  private processCompositeFilters(compositeFilters: CompositeFilter[], filters: SearchFilter[]): void {
    for (const compositeFilter of compositeFilters) {
      this.processStringFilters(compositeFilter.StringFilters, filters);
    }
  }

  /**
   * Converts a search request to internal search criteria format
   * @param request - The search request (FindingsRequest, RemediationsRequest, etc.)
   * @param resourceType - The type of resource being searched for (Findings, Remediations)
   * @returns SearchCriteria for repository layer
   */
  protected async convertToSearchCriteria<T extends SearchRequest>(
    request: T,
    resourceType: ResourceType,
  ): Promise<SearchCriteria> {
    this.assertSupportedFilterFields(request, resourceType);

    const filters: SearchFilter[] = [];
    let hasCompositeFilters = false;

    if (request.Filters?.StringFilters) {
      this.processStringFilters(request.Filters.StringFilters, filters);
    }

    if (request.Filters?.CompositeFilters) {
      hasCompositeFilters = true;
      this.processCompositeFilters(request.Filters.CompositeFilters, filters);
    }

    const sortCriteria = request.SortCriteria?.[0];

    const uniqueFilters = new Set(filters.map((filter) => filter.fieldName));
    await sendMetrics({
      search_operation: {
        filter_types_used: [...uniqueFilters],
        filter_count: filters.length,
        has_composite_filters: hasCompositeFilters,
        sort_fields_used: sortCriteria?.Field ? [sortCriteria.Field] : [], // leaving open to extension with multiple sort fields
        resource_type: resourceType,
      },
    });

    return {
      filters,
      sortField: sortCriteria?.Field,
      sortOrder: sortCriteria?.SortOrder,
      pageSize: DEFAULT_PAGE_SIZE,
      nextToken: request.NextToken,
    };
  }

  /**
   * Whether the request carries an `accountId` filter that will actually reach
   * the repository.
   *
   * Both filter shapes are checked: the original check read only the composite
   * shape, so a root-level accountId filter was treated as absent.
   *
   * The decision delegates to `validateAndConvertStringFilter` so that it cannot
   * drift from what conversion keeps. A filter that conversion drops, for want of
   * a value or a comparison, must not suppress the ceiling: it would be discarded
   * on the way to the query and leave it with no account scope at all.
   */
  private hasAccountIdFilter(request: SearchRequest): boolean {
    const filters = request.Filters;
    if (!filters) {
      return false;
    }

    const stringFilters = [
      ...(filters.StringFilters ?? []),
      ...(filters.CompositeFilters ?? []).flatMap((compositeFilter) => compositeFilter.StringFilters ?? []),
    ];

    return stringFilters.some(
      (stringFilter) =>
        stringFilter.FieldName === 'accountId' &&
        stringFilter.Filter?.Comparison === 'EQUALS' &&
        this.validateAndConvertStringFilter(stringFilter) !== null,
    );
  }

  /**
   * Applies account filtering for account operators by adding authorized account filters
   * @param authenticatedUser - The authenticated user with potential account restrictions
   * @param request - The search request to modify (FindingsRequest, RemediationsRequest, etc.)
   * @returns The same request type with account filters applied if needed
   */
  protected applyAccountFilteringForAccountOperators<T extends SearchRequest>(
    authenticatedUser: AuthenticatedUser,
    request: T,
  ): T {
    if (!authenticatedUser.authorizedAccounts) {
      return request;
    }

    // The ceiling is injected only when the request carries no accountId filter
    // of its own, in which case these are the only accountId filters and their
    // OR is exactly the operator's authorized set.
    //
    // It is deliberately not appended alongside a caller's own accountId filter.
    // The repository groups filters by field and combines a group with OR, so a
    // second accountId filter would widen the scope rather than intersect it,
    // and would also cost the accountId index, which requires a single EQUALS
    // filter on the field. A request that does filter accountId has already been
    // authorized against the operator's accounts by the handler, which rejects
    // both an unauthorized account and a comparison that cannot be narrowed.
    if (this.hasAccountIdFilter(request)) {
      return request;
    }

    const userAllowedAccountIds = authenticatedUser.authorizedAccounts;

    const accountIdFilters = userAllowedAccountIds.map((accountId: string) => ({
      FieldName: 'accountId',
      Filter: {
        Value: accountId,
        Comparison: 'EQUALS' as const,
      },
    }));

    const accountCompositeFilter: CompositeFilter = {
      Operator: 'OR',
      StringFilters: accountIdFilters,
    };

    const modifiedRequest: T = { ...request };
    if (!modifiedRequest.Filters) {
      modifiedRequest.Filters = {
        CompositeFilters: [accountCompositeFilter],
        CompositeOperator: 'AND',
      };
    } else {
      const existingFilters = modifiedRequest.Filters.CompositeFilters || [];
      modifiedRequest.Filters = {
        ...modifiedRequest.Filters,
        CompositeFilters: [...existingFilters, accountCompositeFilter],
        CompositeOperator: 'AND',
      };
    }

    return modifiedRequest;
  }
}
