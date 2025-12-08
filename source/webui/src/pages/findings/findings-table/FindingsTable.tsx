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
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Toggle from '@cloudscape-design/components/toggle';
import { useDispatch } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { ActionsDropdown } from '../../../components/ActionsDropdown.tsx';
import { EmptyTableState } from '../../../components/EmptyTableState.tsx';
import { FindingApiResponse } from '@data-models';
import {
  useExecuteActionMutation,
  useExportFindingsMutation,
  useLazySearchFindingsQuery
} from '../../../store/findingsApiSlice.ts';
import { CompositeFilter, SearchRequest, StringFilter } from '../../../store/types.ts';
import { getErrorMessage } from '../../../utils/error.ts';
import { createColumnDefinitions } from './createColumnDefinitions.tsx';

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;
const getHeaderCounterText = (items: readonly FindingApiResponse[] = [], selectedItems: readonly FindingApiResponse[] = []) => {
  return selectedItems && selectedItems.length > 0 ? `(${selectedItems.length}/${items.length})` : `(${items.length})`;
};

export interface FindingsTableProps {
}

export default function FindingsTable() {
  const navigate = useNavigate();
  useDispatch();

  // State management
  const [preferences, setPreferences] = useState<CollectionPreferencesProps['preferences']>({
    wrapLines: true,
    stripedRows: false,
    contentDensity: 'comfortable',
  });
  const [selectedItems, setSelectedItems] = useState<FindingApiResponse[]>([]);
  const [sortingColumn, setSortingColumn] = useState(() => {
    const columns = createColumnDefinitions(navigate);
    return columns.find(col => col.sortingField === 'securityHubUpdatedAtTime')!;
  });
  const [sortingDescending, setSortingDescending] = useState(true);
  const [filterTokens, setFilterTokens] = useState<PropertyFilterProps.Token[]>([]);
  const [filterOperation, setFilterOperation] = useState<'and' | 'or'>('and');

  const [allFindings, setAllFindings] = useState<FindingApiResponse[]>([]);
  const [nextToken, setNextToken] = useState<string | undefined>();
  const [hasMoreData, setHasMoreData] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [operationType, setOperationType] = useState<'initial' | 'refresh' | 'filter' | 'loadMore'>('initial');
  const [showSuppressed, setShowSuppressed] = useState(false);

  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [pendingAction, setPendingAction] = useState<{
    type: 'remediate' | 'remediateAndTicket' | 'suppress' | 'unsuppress';
    items: readonly FindingApiResponse[];
  } | null>(null);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Ref for scroll detection
  const tableContainerRef = useRef<HTMLDivElement>(null);
  const loadMoreTriggerRef = useRef<HTMLDivElement>(null);

  const [searchFindings, { data: searchResult, isLoading, error: searchError }] = useLazySearchFindingsQuery();
  const [executeAction, { isLoading: isExecutingAction }] = useExecuteActionMutation();
  const [exportFindings, { isLoading: isExportLoading, error: exportError }] = useExportFindingsMutation();

  const getComparisonOperator = (operator: string): 'EQUALS' | 'NOT_EQUALS' | 'CONTAINS' | 'NOT_CONTAINS' => {
    switch (operator) {
      case '=':
        return 'EQUALS';
      case '!=':
        return 'NOT_EQUALS';
      case ':':
        return 'CONTAINS';
      case '!:':
        return 'NOT_CONTAINS';
      default:
        return 'EQUALS';
    }
  };

  const unformatStatus = (formattedStatus: string) => {
    // Convert formatted status back to uppercase with underscores for API call
    const statusMap: { [key: string]: string } = {
      'Success': 'SUCCESS',
      'Failed': 'FAILED',
      'Not Started': 'NOT_STARTED',
      'In Progress': 'IN_PROGRESS'
    };
    
    return statusMap[formattedStatus] || formattedStatus.toUpperCase().replace(/\s+/g, '_');
  };

  const convertTokensToFilters = (tokens: PropertyFilterProps.Token[], operation: string): SearchRequest['Filters'] => {
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

    // Convert field groups to CompositeFilters
    // Each field group becomes a CompositeFilter with OR operator (same field = OR)
    // Different CompositeFilters are combined with AND (different fields = AND)
    const compositeFilters: CompositeFilter[] = Object.entries(fieldGroups).map(([fieldName, filters]) => ({
      Operator: 'OR' as const, // Same field filters use OR
      StringFilters: filters,
    }));

    return {
      CompositeFilters: compositeFilters.length > 0 ? compositeFilters : undefined,
      CompositeOperator: 'AND',
    };
  };

  const buildSearchRequest = (useNextToken: boolean = false): SearchRequest => {
    const filters = convertTokensToFilters(filterTokens, filterOperation);

    const request: SearchRequest = {
      Filters: filters,
      SortCriteria: [{
        Field: sortingColumn.sortingField || 'securityHubUpdatedAtTime',
        SortOrder: sortingDescending ? 'desc' : 'asc',
      }],
    };

    // Add NextToken for loading more data
    if (useNextToken && nextToken) {
      request.NextToken = nextToken;
    }

    return request;
  };

  // Initial load on component mount
  useEffect(() => {
    setOperationType('initial');
    const searchRequest = buildSearchRequest(false);
    searchFindings(searchRequest);
  }, []);

  // Reload when filters or sorting change
  useEffect(() => {
    setOperationType('filter');
    setAllFindings([]);
    setNextToken(undefined);
    setHasMoreData(false);
    
    const searchRequest = buildSearchRequest(false);
    searchFindings(searchRequest);
  }, [filterTokens, filterOperation, sortingColumn, sortingDescending]);

  // Update state when search results change
  useEffect(() => {
    if (searchResult) {
      if (operationType === 'loadMore') {
        setAllFindings(prev => {
          const existingIds = new Set(prev.map(f => f.findingId));
          const newFindings = searchResult.Findings.filter(f => !existingIds.has(f.findingId));
          return [...prev, ...newFindings];
        });
        setIsLoadingMore(false);
      } else {
        // Replace findings (initial, refresh, or filter change)
        setAllFindings(searchResult.Findings);
      }

      setNextToken(searchResult.NextToken);
      setHasMoreData(!!searchResult.NextToken);
      
      // Clear any previous search errors on successful response
      setErrorMessage(null);

      if (operationType === 'refresh' || operationType === 'filter') {
        setOperationType('initial');
      }
    }
  }, [searchResult, operationType]);

  // Handle search errors
  useEffect(() => {
    if (searchError) {
      console.error('Failed to search findings:', searchError);
      const errorMsg = getErrorMessage(searchError) || 'Please try again.';
      setErrorMessage(`Failed to load findings: ${errorMsg}`);

      setIsLoadingMore(false);

      if (operationType !== 'loadMore') {
        setAllFindings([]);
        setNextToken(undefined);
        setHasMoreData(false);
        setSelectedItems([]);
      }

      if (operationType === 'refresh' || operationType === 'filter') {
        setOperationType('initial');
      }
    }
  }, [searchError, operationType]);

  const findings = useMemo(() => {
    if (!Array.isArray(allFindings)) {
      return [];
    }
    

    if (showSuppressed) {
      return allFindings;
    } else {
      return allFindings.filter(finding => !finding.suppressed);
    }
  }, [allFindings, showSuppressed]);

  const filteringProperties = [
    {
      key: 'findingType',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Finding Type',
      groupValuesLabel: 'Finding Type values'
    },
    {
      key: 'accountId',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Account',
      groupValuesLabel: 'Account values'
    },
    {
      key: 'remediationStatus',
      operators: ['=', '!='],
      propertyLabel: 'Remediation Status',
      groupValuesLabel: 'Remediation Status values'
    },
    {
      key: 'findingId',
      operators: ['='],
      propertyLabel: 'Finding ID',
      groupValuesLabel: 'Finding ID values'
    },
    {
      key: 'resourceType',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Resource Type',
      groupValuesLabel: 'Resource Type values'
    },
    {
      key: 'resourceId',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Resource ID',
      groupValuesLabel: 'Resource ID values'
    },
    {
      key: 'severity',
      operators: ['=', '!='],
      propertyLabel: 'Severity',
      groupValuesLabel: 'Severity values'
    }
  ];

  const filteringOptions = useMemo(() => {
    const options: { propertyKey: string; value: string }[] = [];
    const uniqueValues = new Set<string>();

    const remediationStatusOptions = [
      'Success',
      'Failed', 
      'Not Started',
      'In Progress'
    ];
    
    remediationStatusOptions.forEach(status => {
      options.push({ propertyKey: 'remediationStatus', value: status });
    });

    const severityOptions = [
      'INFORMATIONAL',
      'LOW',
      'MEDIUM', 
      'HIGH',
      'CRITICAL'
    ];
    
    severityOptions.forEach(severity => {
      options.push({ propertyKey: 'severity', value: severity });
    });

    findings.forEach(finding => {
      filteringProperties.forEach(prop => {
        // Skip remediationStatus and severity as we're using fixed values
        if (prop.key === 'remediationStatus' || prop.key === 'severity') return;
        
        const value = finding[prop.key as keyof FindingApiResponse];
        if (value && !uniqueValues.has(`${prop.key}:${value}`)) {
          uniqueValues.add(`${prop.key}:${value}`);
          options.push({ propertyKey: prop.key, value: String(value) });
        }
      });
    });

    return options;
  }, [findings]);

  const collectionPreferencesProps = {
    title: 'Preferences',
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    preferences: {
      ...preferences,
      contentDisplay: [
        { id: 'findingType', label: 'Finding Type', visible: preferences?.visibleContent?.includes('findingType') ?? true },
        { id: 'findingDescription', label: 'Finding Title', visible: preferences?.visibleContent?.includes('findingDescription') ?? true },
        { id: 'remediationStatus', label: 'Remediation Status', visible: preferences?.visibleContent?.includes('remediationStatus') ?? true },
        { id: 'accountId', label: 'Account', visible: preferences?.visibleContent?.includes('accountId') ?? true },
        { id: 'findingId', label: 'Finding ID', visible: preferences?.visibleContent?.includes('findingId') ?? true },
        { id: 'resourceType', label: 'Resource Type', visible: preferences?.visibleContent?.includes('resourceType') ?? true },
        { id: 'resourceId', label: 'Resource ID', visible: preferences?.visibleContent?.includes('resourceId') ?? true },
        { id: 'severity', label: 'Severity', visible: preferences?.visibleContent?.includes('severity') ?? true },
        { id: 'securityHubUpdatedAtTime', label: 'Security Hub Updated Time', visible: preferences?.visibleContent?.includes('securityHubUpdatedAtTime') ?? true },
        { id: 'consoleLink', label: 'Finding Link', visible: preferences?.visibleContent?.includes('consoleLink') ?? true },
        ...(showSuppressed ? [{ id: 'suppressed', label: 'Suppressed', visible: preferences?.visibleContent?.includes('suppressed') ?? true }] : []),
      ],
    },
    onConfirm: ({ detail }: any) => {
      // Convert contentDisplay array to visibleContent array
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
        { id: 'findingType', label: 'Finding Type' },
        { id: 'findingDescription', label: 'Finding Title' },
        { id: 'remediationStatus', label: 'Remediation Status' },
        { id: 'accountId', label: 'Account' },
        { id: 'findingId', label: 'Finding ID' },
        { id: 'resourceType', label: 'Resource Type' },
        { id: 'resourceId', label: 'Resource ID' },
        { id: 'severity', label: 'Severity' },
        { id: 'securityHubUpdatedAtTime', label: 'Security Hub Updated Time' },
        { id: 'consoleLink', label: 'Finding Link' },
        ...(showSuppressed ? [{ id: 'suppressed', label: 'Suppressed' }] : []),
      ],
    },
  };

  const allColumnDefinitions = useMemo(() => {
    const columns = createColumnDefinitions(navigate);
    // Add IDs to columns for preferences
    return columns.map((col, index) => ({
      ...col,
      id: [
        'findingType',
        'findingDescription',
        'remediationStatus',
        'accountId',
        'findingId',
        'resourceType',
        'resourceId',
        'severity',
        'securityHubUpdatedAtTime',
        'consoleLink',
        'suppressed'
      ][index]
    }));
  }, [navigate]);

  const columnDefinitions = useMemo(() => {
    if (!preferences?.visibleContent) {
      // Default: show all columns except suppressed
      return allColumnDefinitions.filter(col => col.id !== 'suppressed');
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

  const loadMoreFindings = useCallback(async () => {
    if (!hasMoreData || isLoadingMore || isLoading) return;
    
    setOperationType('loadMore');
    setIsLoadingMore(true);
    
    const searchRequest = buildSearchRequest(true);
    searchFindings(searchRequest);
  }, [hasMoreData, isLoadingMore, isLoading, searchFindings, buildSearchRequest]);

  // Intersection Observer for infinite scroll
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const [entry] = entries;
        if (entry.isIntersecting && hasMoreData && !isLoadingMore && !isLoading) {
          loadMoreFindings();
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
  }, [hasMoreData, isLoadingMore, isLoading, loadMoreFindings]);

  // Alternative scroll-based detection for table container
  useEffect(() => {
    const handleScroll = () => {
      const container = tableContainerRef.current;
      if (!container || !hasMoreData || isLoadingMore || isLoading) return;

      const { scrollTop, scrollHeight, clientHeight } = container;
      const scrollPercentage = (scrollTop + clientHeight) / scrollHeight;

      // Trigger load more when 95% scrolled
      if (scrollPercentage >= 0.95) {
        loadMoreFindings();
      }
    };

    const container = tableContainerRef.current;
    if (container) {
      container.addEventListener('scroll', handleScroll, { passive: true });
      return () => container.removeEventListener('scroll', handleScroll);
    }
  }, [hasMoreData, isLoadingMore, isLoading, loadMoreFindings]);

  const handleRemediate = (items: readonly FindingApiResponse[]) => {
    setPendingAction({ type: 'remediate', items });
    setShowConfirmModal(true);
  };

  const handleRemediateAndGenerateTicket = (items: readonly FindingApiResponse[]) => {
    setPendingAction({ type: 'remediateAndTicket', items });
    setShowConfirmModal(true);
  };

  const handleSuppress = (items: readonly FindingApiResponse[]) => {
    setPendingAction({ type: 'suppress', items });
    setShowConfirmModal(true);
  };

  const handleUnsuppress = (items: readonly FindingApiResponse[]) => {
    setPendingAction({ type: 'unsuppress', items });
    setShowConfirmModal(true);
  };


  // Generic suppress/unsuppress handler
  const handleSuppressionAction = async (
    actionType: 'Suppress' | 'Unsuppress',
    findingIds: string[]
  ) => {
    const suppressValue = actionType === 'Suppress';

    const result = await executeAction({
      actionType,
      findingIds,
    });

    if (!result.error) {
      setAllFindings(prevFindings =>
        prevFindings.map(finding =>
          findingIds.includes(finding.findingId)
            ? { ...finding, suppressed: suppressValue }
            : finding
        )
      );
      console.log(`Successfully ${actionType}ed ${pendingAction?.items.length} finding(s)`);
      setErrorMessage(null);
      setSuccessMessage(`Successfully ${actionType.toLowerCase()}ed ${pendingAction?.items.length} finding${pendingAction?.items.length === 1 ? '' : 's'}`);
    } else {
      console.error(`Failed to ${actionType} findings:`, result.error);
      const errorMsg = getErrorMessage(result.error) || 'Please try again.';
      setErrorMessage(`Failed to ${actionType} findings: ${errorMsg}`);
    }
  };

  const handleSuppressAction = async (findingIds: string[]) => {
    await handleSuppressionAction('Suppress', findingIds);
  };

  const handleUnsuppressAction = async (findingIds: string[]) => {
    await handleSuppressionAction('Unsuppress', findingIds);
  };

  const handleRemediationAction = async (
    actionType: 'Remediate' | 'RemediateAndGenerateTicket',
    findingIds: string[]
  ) => {
    const result = await executeAction({
      actionType,
      findingIds,
    });

    if (!result.error) {
      setAllFindings(prevFindings =>
        prevFindings.map(finding =>
          findingIds.includes(finding.findingId)
            ? { 
                ...finding, 
                remediationStatus: 'IN_PROGRESS' as const,
                lastUpdatedTime: new Date().toISOString()
              }
            : finding
        )
      );
      console.log(`Successfully initiated ${actionType} for ${pendingAction?.items.length} finding(s)`);
      setErrorMessage(null);
      setSuccessMessage(`Successfully sent ${pendingAction?.items.length} finding${pendingAction?.items.length === 1 ? '' : 's'} for Remediation`);
    } else {
      console.error(`Failed to execute ${actionType}:`, result.error);
      const errorMsg = getErrorMessage(result.error) || 'Please try again.';
      setErrorMessage(`Failed to ${actionType}: ${errorMsg}`);
    }
  };

  // Handle remediate action
  const handleRemediateAction = async (findingIds: string[]) => {
    await handleRemediationAction('Remediate', findingIds);
  };

  // Handle remediate and ticket action
  const handleRemediateAndTicketAction = async (findingIds: string[]) => {
    await handleRemediationAction('RemediateAndGenerateTicket', findingIds);
  };

  // Execute the confirmed action
  const executeConfirmedAction = async () => {
    if (!pendingAction || pendingAction.items.length === 0) return;

    try {
      const findingIds = pendingAction.items.map(item => item.findingId);

      switch (pendingAction.type) {
        case 'suppress':
          await handleSuppressAction(findingIds);
          break;
        case 'unsuppress':
          await handleUnsuppressAction(findingIds);
          break;
        case 'remediate':
          await handleRemediateAction(findingIds);
          break;
        case 'remediateAndTicket':
          await handleRemediateAndTicketAction(findingIds);
          break;
      }

      // Clear selection after action
      setSelectedItems([]);

    } catch (error) {
      console.error(`Failed to execute ${pendingAction.type} action:`, error);
    } finally {
      // Close modal and clear pending action
      setShowConfirmModal(false);
      setPendingAction(null);
    }
  };

  // Cancel confirmation modal
  const cancelConfirmation = () => {
    setShowConfirmModal(false);
    setPendingAction(null);
  };

  // Get modal content based on action type
  const getModalContent = () => {
    if (!pendingAction) return { title: '', message: '', actionButton: '' };

    const count = pendingAction.items.length;
    const itemText = count === 1 ? 'finding' : 'findings';

    switch (pendingAction.type) {
      case 'suppress':
        return {
          title: 'Confirm Suppress Action',
          message: `Are you sure you want to suppress ${count} ${itemText}? Suppressed findings will be hidden from the default view but can be shown using the toggle.`,
          actionButton: 'Suppress',
        };
      case 'unsuppress':
        return {
          title: 'Confirm Unsuppress Action',
          message: `Are you sure you want to unsuppress ${count} ${itemText}? Unsuppressed findings will be visible in the default view and available for remediation.`,
          actionButton: 'Unsuppress',
        };
      case 'remediate':
        return {
          title: 'Confirm Remediation',
          message: `Are you sure you want to remediate ${count} ${itemText}? This will automatically make changes to your AWS resources to fix the security issues. Some changes may be irreversible.`,
          actionButton: 'Remediate',
        };
      case 'remediateAndTicket':
        return {
          title: 'Confirm Remediation with Ticket',
          message: `Are you sure you want to remediate ${count} ${itemText} and generate tickets? This will automatically make changes to your AWS resources and create tracking tickets. Some changes may be irreversible.`,
          actionButton: 'Remediate & Create Ticket',
        };
      default:
        return { title: '', message: '', actionButton: '' };
    }
  };

  const handleRefresh = () => {
    setOperationType('refresh');
    setAllFindings([]);
    setNextToken(undefined);
    setHasMoreData(false);
    setSelectedItems([]);
    setErrorMessage(null);
    setSuccessMessage(null);
    setIsLoadingMore(false);

    const searchRequest = buildSearchRequest(false);
    searchFindings(searchRequest);
  };

  const handleExport = async () => {
    try {
      const exportRequest = buildSearchRequest(false);

      const result = await exportFindings(exportRequest).unwrap();
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
      setErrorMessage(`Failed to export findings: ${errorMsg}`);
    }
  };

  return (
    <div>
      {successMessage && (
        <Box margin={{ top: 'xs', bottom: 'xs', horizontal: 'xxxl' }} padding={{ horizontal: 'xxxl' }}>
          <Alert
            type="success"
            dismissible
            onDismiss={() => setSuccessMessage(null)}
            action={
              successMessage.includes('Remediation') ? (
                <Button
                  onClick={() => navigate('/history')}
                >
                  View History
                </Button>
              ) : undefined
            }
          >
            {successMessage}
          </Alert>
        </Box>
      )}

      {errorMessage && (
        <Box margin={{ top: 'xs', bottom: 'xs', horizontal: 'xxxl' }} padding={{ horizontal: 'xxxl' }}>
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

      {/* Header Section */}
      <Header
        variant="h1"
        counter={`(${findings.length}${hasMoreData ? '+' : ''})`}
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            <Button
              iconName="refresh"
              loading={isLoading}
              onClick={handleRefresh}
              ariaLabel="Refresh findings"
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
            <ActionsDropdown
              selectedItems={selectedItems}
              onRemediate={handleRemediate}
              onRemediateAndGenerateTicket={handleRemediateAndGenerateTicket}
              onSuppress={handleSuppress}
              onUnsuppress={handleUnsuppress}
            />
          </SpaceBetween>
        }
        description="View Security Hub findings across all member accounts that are supported for remediation in Automated Security Response on AWS."
      >
        Findings to Remediate
      </Header>

      {/* Single Integrated Search and Filter */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '16px' }}>
        <div style={{ flex: 1 }}>
          <PropertyFilter
            query={{ tokens: filterTokens || [], operation: 'and' }}
            onChange={handleFilterChange}
            filteringProperties={filteringProperties}
            filteringOptions={filteringOptions}
            countText={getFilterCounterText(findings.length)}
            hideOperations={true}
            i18nStrings={{
              filteringAriaLabel: 'Filter findings',
              dismissAriaLabel: 'Dismiss',
              filteringPlaceholder: 'Search Findings',
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

      <Box padding={{ vertical: 's' }}>
        <Toggle
          onChange={({ detail }) => {
            setShowSuppressed(detail.checked);

            if (detail.checked) {
              // Add suppressed column
              const currentVisibleContent = preferences?.visibleContent || [
                'findingType', 'findingDescription', 'remediationStatus', 'accountId',
                'findingId', 'resourceType', 'resourceId', 'severity',
                'securityHubUpdatedAtTime', 'consoleLink'
              ];
              setPreferences({
                ...preferences,
                visibleContent: [...currentVisibleContent, 'suppressed']
              });
            } else {
              // Remove suppressed column
              setPreferences({
                ...preferences,
                visibleContent: (preferences?.visibleContent || []).filter(col => col !== 'suppressed')
              });
            }
          }}
          checked={showSuppressed}
        >
          Show suppressed findings
        </Toggle>
      </Box>

      {/* Table Section with Infinite Scroll */}
      <div ref={tableContainerRef} style={{ position: 'relative' }}>
        <Table<FindingApiResponse>
          items={findings}
          loading={isLoading}
          loadingText="Loading findings"
          columnDefinitions={columnDefinitions}
          selectedItems={selectedItems}
          onSelectionChange={({ detail }) => setSelectedItems(detail.selectedItems)}
          sortingColumn={sortingColumn}
          sortingDescending={sortingDescending}
          onSortingChange={({ detail }) => handleSortingChange(detail)}
          stickyHeader
          stripedRows={preferences?.stripedRows ?? false}
          contentDensity={preferences?.contentDensity ?? 'comfortable'}
          wrapLines={preferences?.wrapLines ?? true}
          variant="full-page"
          selectionType="multi"
          isItemDisabled={(item) =>
            item.remediationStatus === 'IN_PROGRESS' || item.remediationStatus === 'SUCCESS'
          }
          ariaLabels={{
            selectionGroupLabel: 'Items selection',
            tableLabel: 'Findings table',
            allItemsSelectionLabel: ({ selectedItems }) =>
              `${selectedItems.length} ${selectedItems.length === 1 ? 'item' : 'items'} selected`,
            itemSelectionLabel: ({ selectedItems }, item) => {
              const isItemSelected = selectedItems.filter(i => i.findingId === item.findingId).length;
              return `${item.findingDescription} is ${isItemSelected ? '' : 'not '}selected`;
            }
          }}
          empty={<EmptyTableState title="No findings to display" subtitle="" />}
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
                Loading more findings...
              </span>
            </div>
          </Box>
        )}


        {/* End of Results Indicator */}
        {!hasMoreData && findings.length > 0 && (
          <Box textAlign="center" padding="l" color="text-status-inactive" fontSize="heading-s" fontWeight="bold">
            No more findings to load
          </Box>
        )}
      </div>


      {showConfirmModal && pendingAction && (
        <Modal
          onDismiss={cancelConfirmation}
          visible={showConfirmModal}
          header={getModalContent().title}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={cancelConfirmation}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={executeConfirmedAction}
                  loading={isExecutingAction}
                >
                  {getModalContent().actionButton}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            <Box>
              {getModalContent().message}
            </Box>
            {pendingAction.items.length > 0 && (
              <Box>
                <strong>Selected finding IDs:</strong>
                <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
                    {pendingAction.items.slice(0, 5).map((item) => (
                    <li key={item.findingId} style={{ marginBottom: '4px', fontFamily: 'monospace', fontSize: '12px' }}>
                        {item.findingId}
                    </li>
                    ))}
                    {pendingAction.items.length > 5 && (
                    <li style={{ fontStyle: 'italic', color: '#666' }}>
                        ... and {pendingAction.items.length - 5} more finding(s)
                    </li>
                    )}
                </ul>
              </Box>
            )}
          </SpaceBetween>
        </Modal>
      )}
    </div>
  );
}
