// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { SearchCriteria, SearchFilter } from '@asr/data-models';
import { AuthenticatedUser } from './authorization';
import { DEFAULT_PAGE_SIZE } from '../../common/constants/apiConstant';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { normalizeResourceType } from '../../common/services/findingDataService';
import { FindingAbstractData } from '@asr/data-models';

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
   * Validates if a string filter has all required fields
   * @param stringFilter - The string filter to validate
   * @returns true if the filter is valid
   */
  protected isValidStringFilter(stringFilter: StringFilter): boolean {
    return this.validateAndConvertStringFilter(stringFilter) !== null;
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

    const hasAccountIdInStringFilters = request.Filters?.StringFilters?.some(
      (stringFilter) => stringFilter.FieldName === 'accountId' && this.isValidStringFilter(stringFilter),
    );

    const hasAccountIdInCompositeFilters = request.Filters?.CompositeFilters?.some((compositeFilter) =>
      compositeFilter.StringFilters?.some(
        (stringFilter) => stringFilter.FieldName === 'accountId' && this.isValidStringFilter(stringFilter),
      ),
    );

    const hasAccountIdFilter = hasAccountIdInStringFilters || hasAccountIdInCompositeFilters;

    if (hasAccountIdFilter) {
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
