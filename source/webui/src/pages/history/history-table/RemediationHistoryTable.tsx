// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import CollectionPreferences, {
  CollectionPreferencesProps,
} from '@cloudscape-design/components/collection-preferences';
import Header from '@cloudscape-design/components/header';
import PropertyFilter, { PropertyFilterProps } from '@cloudscape-design/components/property-filter';
import Table from '@cloudscape-design/components/table';

import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import { useDispatch } from 'react-redux';
import { useLocation, useNavigate } from 'react-router-dom';
import { EmptyTableState } from '../../../components/EmptyTableState.tsx';
import { RemediationHistoryApiResponse } from '@data-models';
import { useExportRemediationsMutation, useLazySearchRemediationsQuery } from '../../../store/remediationsSlice.ts';
import { CompositeFilter, SearchRequest, StringFilter } from '../../../store/types.ts';
import { getErrorMessage } from '../../../utils/error.ts';
import { createHistoryColumnDefinitions } from './createHistoryColumnDefinitions.tsx';

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;

export default function RemediationHistoryTable() {
  const navigate = useNavigate();
  const location = useLocation();
  useDispatch();

  // State management
  const [preferences, setPreferences] = useState<CollectionPreferencesProps['preferences']>({
    wrapLines: true,
    stripedRows: false,
    contentDensity: 'comfortable',
  });
  const [sortingColumn, setSortingColumn] = useState(() => {
    const columns = createHistoryColumnDefinitions(navigate);
    return columns.find(col => col.sortingField === 'lastUpdatedTime')!;
  });
  const [sortingDescending, setSortingDescending] = useState(true);
  const [filterTokens, setFilterTokens] = useState<PropertyFilterProps.Token[]>([]);
  const [filterOperation, setFilterOperation] = useState<'and' | 'or'>('and');

  const [allHistory, setAllHistory] = useState<RemediationHistoryApiResponse[]>([]);
  const [nextToken, setNextToken] = useState<string | undefined>();
  const [hasMoreData, setHasMoreData] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [operationType, setOperationType] = useState<'initial' | 'refresh' | 'filter' | 'loadMore'>('initial');

  // Refs for scroll detection
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const loadMoreTriggerRef = useRef<HTMLDivElement>(null);

  const [searchRemediations, { data: searchResult, isLoading: isSearchLoading, error: searchError }] = useLazySearchRemediationsQuery();
  const [exportRemediations, { isLoading: isExportLoading, error: exportError }] = useExportRemediationsMutation();

  // Handle initial filter state from navigation
  useEffect(() => {
    const state = location.state as { filterTokens?: PropertyFilterProps.Token[] };
    if (state?.filterTokens) {
      setFilterTokens(state.filterTokens);
    }
  }, [location.state]);

  const getComparisonOperator = (operator: string): 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'NOT_CONTAINS' | 'GREATER_THAN_OR_EQUAL' | 'LESS_THAN_OR_EQUAL' => {
    switch (operator) {
      case '=':
        return 'EQUALS';
      case '!=':
        return 'NOT_EQUALS';
      case ':':
        return 'CONTAINS';
      case '!:':
        return 'NOT_CONTAINS';
      case '>=':
        return 'GREATER_THAN_OR_EQUAL';
      case '<=':
        return 'LESS_THAN_OR_EQUAL';
      default:
        return 'EQUALS';
    }
  };

  const unformatStatus = (formattedStatus: string) => {
    // Convert formatted status back to uppercase with underscores for API
    const statusMap: { [key: string]: string } = {
      'Success': 'SUCCESS',
      'Failed': 'FAILED',
      'Not Started': 'NOT_STARTED',
      'In Progress': 'IN_PROGRESS'
    };
    
    return statusMap[formattedStatus] || formattedStatus.toUpperCase().replace(/\s+/g, '_');
  };

  const convertTokensToFilters = (tokens: PropertyFilterProps.Token[]): SearchRequest['Filters'] => {
    if (!tokens?.length) return undefined;

    const fieldGroups: { [fieldName: string]: StringFilter[] } = {};

    tokens.forEach(token => {
      const comparison = getComparisonOperator(token.operator || '=');
      
      // Convert formatted remediation status values back to raw values for API
      let filterValue = token.value || '';
      if (token.propertyKey === 'remediationStatus') {
        filterValue = unformatStatus(filterValue);
      }

      const filter: StringFilter = {
        FieldName: token.propertyKey || '',
        Filter: {
          Value: filterValue,
          Comparison: comparison,
        },
      };

      const fieldName = token.propertyKey || '';
      if (!fieldGroups[fieldName]) {
        fieldGroups[fieldName] = [];
      }
      fieldGroups[fieldName].push(filter);
    });

    const compositeFilters: CompositeFilter[] = Object.entries(fieldGroups).map(([, filters]) => ({
      Operator: 'OR' as const,
      StringFilters: filters,
    }));

    return {
      CompositeFilters: compositeFilters.length > 0 ? compositeFilters : undefined,
      CompositeOperator: 'AND',
    };
  };

  const buildSearchRequest = (useNextToken: boolean = false): SearchRequest => {
    const filters = convertTokensToFilters(filterTokens);

    const request: SearchRequest = {
      Filters: filters,
      SortCriteria: [{
        Field: sortingColumn.sortingField || 'lastUpdatedTime',
        SortOrder: sortingDescending ? 'desc' : 'asc',
      }],
    };

    if (useNextToken && nextToken) {
      request.NextToken = nextToken;
    }

    return request;
  };

  // Initial load on component mount
  useEffect(() => {
    setOperationType('initial');
    const searchRequest = buildSearchRequest(false);
    searchRemediations(searchRequest);
  }, []);

  // Reload when filters or sorting change
  useEffect(() => {
    setOperationType('filter');
    setAllHistory([]);
    setNextToken(undefined);
    setHasMoreData(false);
    
    const searchRequest = buildSearchRequest(false);
    searchRemediations(searchRequest);
  }, [filterTokens, filterOperation, sortingColumn, sortingDescending]);

  // Update state when search results change
  useEffect(() => {
    if (searchResult) {
      if (operationType === 'loadMore') {
        setAllHistory(prev => {
          const existingIds = new Set(prev.map(f => f.executionId));
          const newRemediations = searchResult.Remediations.filter(f => !existingIds.has(f.executionId));
          return [...prev, ...newRemediations];
        });
        setIsLoadingMore(false);
      } else {
        // Replace history (initial, refresh, or filter change)
        setAllHistory(searchResult.Remediations);
      }

      setNextToken(searchResult.NextToken);
      setHasMoreData(!!searchResult.NextToken);

      // Clear any previous search errors on successful response
      setErrorMessage(null);

      // Reset operation type after successful operation (but not for loadMore)
      if (operationType === 'refresh' || operationType === 'filter') {
        setOperationType('initial');
      }
    }
  }, [searchResult, operationType]);

  // Handle search errors
  useEffect(() => {
    if (searchError) {
      console.error('Failed to search remediations:', searchError);
      const errorMsg = getErrorMessage(searchError) || 'Please try again.';
      setErrorMessage(`Failed to load remediation history: ${errorMsg}`);

      setIsLoadingMore(false);

      // clear history when search fails
      if (operationType !== 'loadMore') {
        setAllHistory([]);
        setNextToken(undefined);
        setHasMoreData(false);
      }

      // Reset operation type on error to prevent stuck states (but not for loadMore)
      if (operationType === 'refresh' || operationType === 'filter') {
        setOperationType('initial');
      }
    }
  }, [searchError, operationType]);

  // Handle export errors
  useEffect(() => {
    if (exportError) {
      console.error('Failed to export remediations:', exportError);
      const errorMsg = getErrorMessage(exportError) || 'Please try again.';
      setErrorMessage(`Failed to export remediation history: ${errorMsg}`);
    }
  }, [exportError]);

  const history = useMemo(() => {
    if (!Array.isArray(allHistory)) {
      return [];
    }

    return allHistory;
  }, [allHistory]);

  const filteringProperties = [
    {
      key: 'findingId',
      operators: ['='],
      propertyLabel: 'Finding ID',
      groupValuesLabel: 'Finding ID values'
    },
    {
      key: 'remediationStatus',
      operators: ['=', '!='],
      propertyLabel: 'Status',
      groupValuesLabel: 'Status values'
    },
    {
      key: 'accountId',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Account',
      groupValuesLabel: 'Account values'
    },
    {
      key: 'resourceId',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Resource ID',
      groupValuesLabel: 'Resource ID values'
    },
    {
      key: 'lastUpdatedBy',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Executed By',
      groupValuesLabel: 'Executed By values'
    },
    {
      key: 'lastUpdatedTime',
      operators: ['>=', '<='],
      propertyLabel: 'Execution Timestamp',
      groupValuesLabel: 'DateTime values (e.g., 2024-01-15T14:30)'
    }
  ];

  const filteringOptions = useMemo(() => {
    const options: { propertyKey: string; value: string }[] = [];
    const uniqueValues = new Set<string>();

    // Add fixed formatted status values
    const statusOptions = [
      'Success',
      'Failed', 
      'Not Started',
      'In Progress'
    ];
    
    statusOptions.forEach(status => {
      options.push({ propertyKey: 'remediationStatus', value: status });
      uniqueValues.add(`remediationStatus:${status}`);
    });

    // Add timestamp format examples for better UX
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    const lastWeek = new Date(today);
    lastWeek.setDate(lastWeek.getDate() - 7);
    const lastMonth = new Date(today);
    lastMonth.setMonth(lastMonth.getMonth() - 1);

    const timestampExamples = [
      today.toISOString().substring(0, 16),
      yesterday.toISOString().substring(0, 16),
      today.toISOString().split('T')[0],
      yesterday.toISOString().split('T')[0],
    ];

    timestampExamples.forEach(value => {
      if (!uniqueValues.has(`lastUpdatedTime:${value}`)) {
        options.push({ propertyKey: 'lastUpdatedTime', value });
        uniqueValues.add(`lastUpdatedTime:${value}`);
      }
    });

    // Add dynamic values for other fields (excluding remediationStatus and lastUpdatedTime)
    if (Array.isArray(allHistory)) {
      allHistory.forEach(item => {
        filteringProperties.forEach(prop => {
          if (prop.key === 'remediationStatus' || prop.key === 'lastUpdatedTime') return; // Skip these

          const value = item[prop.key as keyof RemediationHistoryApiResponse];
          if (value && !uniqueValues.has(`${prop.key}:${value}`)) {
            uniqueValues.add(`${prop.key}:${value}`);
            options.push({ propertyKey: prop.key, value: String(value) });
          }
        });
      });
    }

    return options;
  }, [allHistory]);

  const collectionPreferencesProps = {
    title: 'Preferences',
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    preferences: {
      ...preferences,
      contentDisplay: [
        { id: 'findingId', label: 'Finding ID', visible: preferences?.visibleContent?.includes('findingId') ?? true },
        { id: 'status', label: 'Status', visible: preferences?.visibleContent?.includes('status') ?? true },
        { id: 'accountId', label: 'Account', visible: preferences?.visibleContent?.includes('accountId') ?? true },
        { id: 'resourceId', label: 'Resource ID', visible: preferences?.visibleContent?.includes('resourceId') ?? true },
        { id: 'executionTimestamp', label: 'Execution Timestamp', visible: preferences?.visibleContent?.includes('executionTimestamp') ?? true },
        { id: 'executedBy', label: 'Executed By', visible: preferences?.visibleContent?.includes('executedBy') ?? true },
        { id: 'viewExecution', label: 'View Execution', visible: preferences?.visibleContent?.includes('viewExecution') ?? true },
      ],
    },
    onConfirm: ({ detail }: any) => {
      const visibleContent = detail.contentDisplay
        .filter((item: any) => item.visible)
        .map((item: any) => item.id);

      setPreferences({
        ...preferences,
        visibleContent,
      });
    },
    contentDisplayPreference: {
      title: 'Column preferences',
      description: 'Choose which columns to display in the table',
      options: [
        { id: 'findingId', label: 'Finding ID' },
        { id: 'status', label: 'Status' },
        { id: 'accountId', label: 'Account' },
        { id: 'resourceId', label: 'Resource ID' },
        { id: 'executionTimestamp', label: 'Execution Timestamp' },
        { id: 'executedBy', label: 'Executed By' },
        { id: 'viewExecution', label: 'View Execution' },
      ],
    },
  };

  const allColumnDefinitions = useMemo(() => {
    const columns = createHistoryColumnDefinitions(navigate);
    // Add IDs to columns for preferences
    return columns.map((col, index) => ({
      ...col,
      id: [
        'findingId',
        'status',
        'accountId',
        'resourceId',
        'executionTimestamp',
        'executedBy',
        'viewExecution'
      ][index]
    }));
  }, [navigate]);

  const columnDefinitions = useMemo(() => {
    if (!preferences?.visibleContent) {
      // Default: show all columns
      return allColumnDefinitions;
    }

    return allColumnDefinitions.filter(col => preferences.visibleContent!.includes(col.id));
  }, [allColumnDefinitions, preferences?.visibleContent]);

  const handleFilterChange = ({ detail }: any) => {
    setFilterTokens(detail.tokens || []);
    setFilterOperation(detail.operation || 'and');
  };

  const handleSortingChange = (detail: any) => {
    setSortingColumn(detail.sortingColumn);
    setSortingDescending(detail.isDescending);
  };

  const loadMoreRemediations = useCallback(async () => {
    if (!hasMoreData || isLoadingMore || isSearchLoading) return;

    setOperationType('loadMore');
    setIsLoadingMore(true);

    const searchRequest = buildSearchRequest(true);
    searchRemediations(searchRequest);
  }, [hasMoreData, isLoadingMore, isSearchLoading, searchRemediations, buildSearchRequest]);

  // Intersection Observer for infinite scroll
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const [entry] = entries;
        if (entry.isIntersecting && hasMoreData && !isLoadingMore && !isSearchLoading) {
          loadMoreRemediations();
        }
      },
      {
        root: null,
        rootMargin: '50px', // Trigger 50px before reaching the element
        threshold: 0.1,
      }
    );

    const currentTrigger = loadMoreTriggerRef.current;
    if (currentTrigger) {
      observer.observe(currentTrigger);
    }

    return () => {
      if (currentTrigger) {
        observer.unobserve(currentTrigger);
      }
    };
  }, [hasMoreData, isLoadingMore, isSearchLoading, loadMoreRemediations]);

  // Alternative scroll-based detection for table container
  useEffect(() => {
    const handleScroll = () => {
      const container = tableContainerRef.current;
      if (!container || !hasMoreData || isLoadingMore || isSearchLoading) return;

      const { scrollTop, scrollHeight, clientHeight } = container;
      const scrollPercentage = (scrollTop + clientHeight) / scrollHeight;

      // Trigger load more when 95% scrolled
      if (scrollPercentage >= 0.95) {
        loadMoreRemediations();
      }
    };

    const container = tableContainerRef.current;
    if (container) {
      container.addEventListener('scroll', handleScroll, { passive: true });
      return () => container.removeEventListener('scroll', handleScroll);
    }
  }, [hasMoreData, isLoadingMore, isSearchLoading, loadMoreRemediations]);

  const handleRefresh = () => {
    setOperationType('refresh');
    setAllHistory([]);
    setNextToken(undefined);
    setHasMoreData(false);
    setErrorMessage(null);
    setIsLoadingMore(false);

    const searchRequest = buildSearchRequest(false);
    searchRemediations(searchRequest);
  };

  const handleExport = async () => {
    try {
      const exportRequest = buildSearchRequest(false);

      const result = await exportRemediations(exportRequest).unwrap();
      if (result.downloadUrl) {
        window.open(result.downloadUrl, '_blank');

        if (result.status === 'partial') {
          setErrorMessage(
            `Partial Export: Exported ${result.totalExported.toLocaleString()} records. ${result.message || ''}`
          );
        }
      }
    } catch (error) {
      console.error('Export failed:', error);
      const errorMsg = getErrorMessage(error) || 'Please try again.';
      setErrorMessage(`Failed to export remediation history: ${errorMsg}`);
    }
  };


  return (
    <div>
      
      {/* Header Section */}
      <Header
        variant="h1"
        counter={`(${history.length}${hasMoreData ? '+' : ''})`}
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            <Button
              iconName="refresh"
              loading={isSearchLoading}
              onClick={handleRefresh}
              ariaLabel="Refresh history"
            />
            <Button
              iconName="download"
              loading={isExportLoading}
              onClick={handleExport}
              ariaLabel="Export to CSV"
              variant="normal"
            >
              Export CSV
            </Button>
          </SpaceBetween>
        }
        description="View remediations executed in the past for all member accounts."
      >
        Remediation History
      </Header>

      {errorMessage && (
        <Box margin={{ bottom: 's' }}>
          <Alert
            type="error"
            dismissible
            onDismiss={() => setErrorMessage(null)}
            header="Operation Failed"
          >
            {errorMessage}
          </Alert>
        </Box>
      )}

      {/* Search and Filter */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '16px' }}>
        <div style={{ flex: 1 }}>
          <PropertyFilter
            query={{ tokens: filterTokens || [], operation: 'and' }}
            onChange={handleFilterChange}
            filteringProperties={filteringProperties}
            filteringOptions={filteringOptions}
            countText={getFilterCounterText(history.length)}
            hideOperations={true}
            i18nStrings={{
              filteringAriaLabel: 'Filter history',
              dismissAriaLabel: 'Dismiss',
              filteringPlaceholder: 'Search Remediations',
              groupValuesText: 'Values',
              groupPropertiesText: 'Properties',
              operatorsText: 'Operators',
              operationAndText: 'and',
              operationOrText: 'or',
              operatorLessText: 'Less than',
              operatorLessOrEqualText: 'Less than or equal',
              operatorGreaterText: 'Greater than',
              operatorGreaterOrEqualText: 'Greater than or equal',
              operatorContainsText: 'Contains',
              operatorDoesNotContainText: 'Does not contain',
              operatorEqualsText: 'Equals',
              operatorDoesNotEqualText: 'Does not equal',
              editTokenHeader: 'Edit filter',
              propertyText: 'Property',
              operatorText: 'Operator',
              valueText: 'Value',
              cancelActionText: 'Cancel',
              applyActionText: 'Apply',
              allPropertiesLabel: 'All properties',
              tokenLimitShowMore: 'Show more',
              tokenLimitShowFewer: 'Show fewer',
              clearFiltersText: 'Clear filters',
              removeTokenButtonAriaLabel: (token) => `Remove token ${token.propertyKey} ${token.operator} ${token.value}`,
              enteredTextLabel: (text) => `Use: "${text}"`
            }}
            expandToViewport
          />
        </div>
        <CollectionPreferences {...collectionPreferencesProps} />
      </div>

      {/* Table Section with Infinite Scroll */}
      <div ref={tableContainerRef} style={{ position: 'relative' }}>
        <Table<RemediationHistoryApiResponse>
          items={history}
          loading={isSearchLoading}
          loadingText="Loading history"
          columnDefinitions={columnDefinitions}
          sortingColumn={sortingColumn}
          sortingDescending={sortingDescending}
          onSortingChange={({ detail }) => handleSortingChange(detail)}
          stickyHeader
          stripedRows={preferences?.stripedRows ?? false}
          contentDensity={preferences?.contentDensity ?? 'comfortable'}
          wrapLines={preferences?.wrapLines ?? true}
          variant="full-page"
          ariaLabels={{
            tableLabel: 'Remediation history table'
          }}
          empty={<EmptyTableState title="No history to display" subtitle="" />}
        />

        {/* Invisible trigger element for intersection observer */}
        {hasMoreData && (
          <div
            ref={loadMoreTriggerRef}
            style={{
              height: '1px',
              width: '100%',
              position: 'absolute',
              bottom: '50px', // Trigger 50px before the actual end
              pointerEvents: 'none',
            }}
          />
        )}

        {/* Loading More Indicator */}
        {isLoadingMore && (
          <Box textAlign="center" padding="l" fontWeight="bold">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
              <Spinner size="normal" />
              <span>
                Loading more remediations...
              </span>
            </div>
          </Box>
        )}

        {/* End of Results Indicator */}
        {!hasMoreData && history.length > 0 && (
          <Box textAlign="center" padding="l" color="text-status-inactive" fontSize="heading-s" fontWeight="bold">
            No more remediations to load
          </Box>
        )}
      </div>
    </div>
  );
}
