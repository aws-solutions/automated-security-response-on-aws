// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import CollectionPreferences, {
  CollectionPreferencesProps,
} from '@cloudscape-design/components/collection-preferences';
import Header from '@cloudscape-design/components/header';
import PropertyFilter, { PropertyFilterProps } from '@cloudscape-design/components/property-filter';
import Table, { TableProps } from '@cloudscape-design/components/table';

import Alert from '@cloudscape-design/components/alert';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Modal from '@cloudscape-design/components/modal';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Toggle from '@cloudscape-design/components/toggle';
import { useNavigate, useSearchParams } from 'react-router';
import { findingsTablePreferences } from '../../../utils/tablePreferences.ts';
import { ActionsDropdown } from '../../../components/ActionsDropdown.tsx';
import { EmptyTableState } from '../../../components/EmptyTableState.tsx';
import { FindingApiResponse, REMEDIATION_STATUS_DISPLAY_OPTIONS, denormalizeRemediationStatus } from '@data-models';
import {
  useExecuteActionMutation,
  useExportFindingsMutation,
  useLazySearchFindingsQuery,
} from '../../../store/findingsApiSlice.ts';
import { CompositeFilter, SearchRequest, StringFilter } from '../../../store/types.ts';
import { getErrorMessage } from '../../../utils/error.ts';
import { createColumnDefinitions, DEFAULT_VISIBLE_COLUMNS } from './createColumnDefinitions.tsx';
import { buildFailedFindingsMessage, executeFindingActionInBatches } from './findingsActionBatch.ts';

const FINDING_TYPE_GUARDDUTY_IAM_USER = 'GuardDuty.IAMUser';
const FINDING_TYPE_MACIE_SENSITIVE_DATA = 'Macie.SensitiveDataS3Object';

// Warning Alert headers, chosen dynamically by applyActionWarning so a batch
// failure is never shown under the "skipped" heading and a mixed outcome reads
// correctly.
const WARNING_HEADER_SKIPPED = 'Some findings were skipped';
const WARNING_HEADER_FAILED = 'Some findings could not be submitted';
const WARNING_HEADER_SKIPPED_AND_FAILED = 'Some findings were skipped or could not be submitted';

type ModalContent = { title: string; message: string; actionButton: string };

function getRemediationModalContent(items: readonly FindingApiResponse[], count: number): ModalContent {
  const itemText = count === 1 ? 'finding' : 'findings';
  const isAllGuardDuty = items.every((item) => item.findingType === FINDING_TYPE_GUARDDUTY_IAM_USER);
  const isAllMacie = items.every((item) => item.findingType === FINDING_TYPE_MACIE_SENSITIVE_DATA);
  const hasMixedSpecialTypes =
    !isAllGuardDuty &&
    !isAllMacie &&
    items.some(
      (item) =>
        item.findingType === FINDING_TYPE_GUARDDUTY_IAM_USER || item.findingType === FINDING_TYPE_MACIE_SENSITIVE_DATA,
    );

  if (isAllGuardDuty) {
    return {
      title: 'Confirm GuardDuty Credential Containment',
      message:
        `This is a first-line defense action. ASR will disable the compromised IAM access keys, ` +
        `remove console access, and attach a deny-all policy to contain the threat.\n\n` +
        `Manual investigation is required after containment: review CloudTrail logs, assess the scope ` +
        `of any unauthorized activity, and decide whether to restore or permanently revoke the IAM principal.\n\n` +
        `You can roll back the containment from the History page once the investigation is complete.`,
      actionButton: 'Contain Credentials',
    };
  }
  if (isAllMacie) {
    return {
      title: 'Confirm Macie Sensitive Data Protection',
      message:
        `This is a first-line defense action. ASR will enable all four S3 Block Public Access settings ` +
        `on the bucket containing sensitive data detected by Macie.\n\n` +
        `Manual investigation is required after protection: review the sensitive data finding, assess ` +
        `the scope of potential exposure, and determine whether the data should be deleted, encrypted, ` +
        `or relocated. Check compliance implications (GDPR, HIPAA, PCI-DSS) if applicable.`,
      actionButton: 'Enable Block Public Access',
    };
  }
  // Mixed selection or generic findings
  const findingTypeNote = hasMixedSpecialTypes
    ? ` Your selection includes findings of different types (e.g. GuardDuty, Macie, and others) that may be remediated through different mechanisms.`
    : '';
  return {
    title: 'Confirm Remediation',
    message: `Are you sure you want to remediate ${count} ${itemText}? This will automatically make changes to your AWS resources to fix the security issues. Some changes may be irreversible.${findingTypeNote}`,
    actionButton: 'Remediate',
  };
}

const getFilterCounterText = (count = 0) => `${count} ${count === 1 ? 'match' : 'matches'}`;

// Maximum number of findings a user may select for a single bulk action. This
// is a UX/performance bound on how much is acted on at once, not a transport
// limit: the findings action requests are BATCHED under the hood (see
// FINDINGS_ACTION_BATCH_SIZE), so no single HTTP request ever carries the whole
// selection. That decouples this cap from the WAF 8 KB body limit — the cap can
// be raised without risking an oversized request. This constant is the single
// source of truth for both the per-row selection cap and the select-all cap so
// the two can never drift apart.
export const SELECTION_LIMIT = 100;

// A finding cannot be selected while it is already being acted on or has been
// remediated. This is the sole eligibility rule, shared by the row-disable
// predicate and the selection cap so both stay consistent.
export function isFindingIneligibleForSelection(finding: FindingApiResponse): boolean {
  return finding.remediationStatus === 'IN_PROGRESS' || finding.remediationStatus === 'SUCCESS';
}

// A row is disabled when the finding is ineligible, or when the cap has been
// reached and the row is not already part of the selection. Once the count
// drops back below the cap every eligible row becomes selectable again.
export function isRowSelectionDisabled(
  finding: FindingApiResponse,
  selectedItems: readonly FindingApiResponse[],
  limit: number,
): boolean {
  if (isFindingIneligibleForSelection(finding)) {
    return true;
  }
  const atLimit = selectedItems.length >= limit;
  const alreadySelected = selectedItems.some((selected) => selected.findingId === finding.findingId);
  return atLimit && !alreadySelected;
}

// Reduce the selection Cloudscape reports down to what the table will hold:
// filtering the display-order list (rather than the reported set) keeps the
// result in Display_Order, dropping ineligible findings and slicing to the cap.
export function limitFindingSelection(
  reportedSelection: readonly FindingApiResponse[],
  findingsInDisplayOrder: readonly FindingApiResponse[],
  limit: number,
): FindingApiResponse[] {
  const reportedIds = new Set(reportedSelection.map((finding) => finding.findingId));
  return findingsInDisplayOrder
    .filter((finding) => reportedIds.has(finding.findingId) && !isFindingIneligibleForSelection(finding))
    .slice(0, limit);
}

export default function FindingsTable() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const persistedPreferences = findingsTablePreferences.load();

  // State management
  const [preferences, setPreferences] = useState<CollectionPreferencesProps['preferences']>(() => {
    const visibleContent =
      persistedPreferences.visibleContent ||
      (persistedPreferences.showSuppressed ? [...DEFAULT_VISIBLE_COLUMNS, 'suppressed'] : [...DEFAULT_VISIBLE_COLUMNS]);

    return {
      wrapLines: true,
      stripedRows: false,
      contentDensity: 'comfortable',
      visibleContent,
    };
  });
  const [selectedItems, setSelectedItems] = useState<FindingApiResponse[]>([]);
  const [sortingColumn, setSortingColumn] = useState<TableProps.SortingColumn<FindingApiResponse>>(() => {
    const columns = createColumnDefinitions(navigate);
    return (
      columns.find((col) => col.sortingField === persistedPreferences.sortingField) ??
      columns.find((col) => col.sortingField === 'securityHubUpdatedAtTime') ??
      columns[0] // Fallback to first column (columns array is never empty)
    );
  });
  const [sortingDescending, setSortingDescending] = useState(persistedPreferences.sortingDescending);
  const [filterTokens, setFilterTokens] = useState<PropertyFilterProps.Token[]>(() => {
    const findingIdFromUrl = searchParams.get('findingId');
    if (findingIdFromUrl) {
      return [{ propertyKey: 'findingId', operator: '=', value: findingIdFromUrl }];
    }
    return persistedPreferences.filterTokens;
  });
  const [filterOperation, setFilterOperation] = useState<'and' | 'or'>('and');

  useEffect(() => {
    if (searchParams.has('findingId')) {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.delete('findingId');
          return next;
        },
        { replace: true },
      );
    }
  }, []);

  const [allFindings, setAllFindings] = useState<FindingApiResponse[]>([]);
  const [nextToken, setNextToken] = useState<string | undefined>();
  const [hasMoreData, setHasMoreData] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [operationType, setOperationType] = useState<'initial' | 'refresh' | 'filter' | 'loadMore'>('initial');
  const [showSuppressed, setShowSuppressed] = useState(persistedPreferences.showSuppressed);

  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [pendingAction, setPendingAction] = useState<{
    type: 'remediate' | 'remediateAndTicket' | 'suppress' | 'unsuppress';
    items: readonly FindingApiResponse[];
  } | null>(null);

  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [warningMessage, setWarningMessage] = useState<string | null>(null);
  const [warningHeader, setWarningHeader] = useState<string>(WARNING_HEADER_SKIPPED);

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
    // Convert formatted status back to the raw value persisted on the findings
    // table for the API filter. Shared with the schema so new statuses (e.g.
    // rollback lifecycle) never need a second hand-maintained list here.
    return denormalizeRemediationStatus(formattedStatus);
  };

  const convertTokensToFilters = (tokens: PropertyFilterProps.Token[], operation: string): SearchRequest['Filters'] => {
    if (!tokens?.length) return undefined;

    const fieldGroups: { [fieldName: string]: StringFilter[] } = {};

    tokens.forEach((token) => {
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
      SortCriteria: [
        {
          Field: sortingColumn?.sortingField || 'securityHubUpdatedAtTime',
          SortOrder: sortingDescending ? 'desc' : 'asc',
        },
      ],
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
        setAllFindings((prev) => {
          const existingIds = new Set(prev.map((f) => f.findingId));
          const newFindings = searchResult.Findings.filter((f) => !existingIds.has(f.findingId));
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
      return allFindings.filter((finding) => !finding.suppressed);
    }
  }, [allFindings, showSuppressed]);

  // Whenever the displayed findings change (filter, sort, show-suppressed
  // toggle, refresh, or infinite-scroll append), reconcile the stored selection
  // so it stays a subset of the currently-displayed selectable findings.
  // Depends only on [findings] and uses the functional-updater form so it
  // cannot cycle and does not re-run on selection changes.
  useEffect(() => {
    setSelectedItems((current) => limitFindingSelection(current, findings, SELECTION_LIMIT));
  }, [findings]);

  const filteringProperties = [
    {
      key: 'findingType',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Finding Type',
      groupValuesLabel: 'Finding Type values',
    },
    {
      key: 'accountId',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Account',
      groupValuesLabel: 'Account values',
    },
    {
      key: 'remediationStatus',
      operators: ['=', '!='],
      propertyLabel: 'Remediation Status',
      groupValuesLabel: 'Remediation Status values',
    },
    {
      key: 'findingId',
      operators: ['='],
      propertyLabel: 'Finding ID',
      groupValuesLabel: 'Finding ID values',
    },
    {
      key: 'resourceType',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Resource Type',
      groupValuesLabel: 'Resource Type values',
    },
    {
      key: 'resourceId',
      operators: ['=', '!=', ':', '!:'],
      propertyLabel: 'Resource ID',
      groupValuesLabel: 'Resource ID values',
    },
    {
      key: 'severity',
      operators: ['=', '!='],
      propertyLabel: 'Severity',
      groupValuesLabel: 'Severity values',
    },
  ];

  const filteringOptions = useMemo(() => {
    const options: { propertyKey: string; value: string }[] = [];
    const uniqueValues = new Set<string>();

    const remediationStatusOptions = REMEDIATION_STATUS_DISPLAY_OPTIONS;

    remediationStatusOptions.forEach((status) => {
      options.push({ propertyKey: 'remediationStatus', value: status });
    });

    const severityOptions = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

    severityOptions.forEach((severity) => {
      options.push({ propertyKey: 'severity', value: severity });
    });

    findings.forEach((finding) => {
      filteringProperties.forEach((prop) => {
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
        {
          id: 'findingType',
          label: 'Finding Type',
          visible: preferences?.visibleContent?.includes('findingType') ?? true,
        },
        {
          id: 'findingDescription',
          label: 'Finding Title',
          visible: preferences?.visibleContent?.includes('findingDescription') ?? true,
        },
        {
          id: 'remediationStatus',
          label: 'Remediation Status',
          visible: preferences?.visibleContent?.includes('remediationStatus') ?? true,
        },
        { id: 'accountId', label: 'Account', visible: preferences?.visibleContent?.includes('accountId') ?? true },
        { id: 'findingId', label: 'Finding ID', visible: preferences?.visibleContent?.includes('findingId') ?? true },
        {
          id: 'resourceType',
          label: 'Resource Type',
          visible: preferences?.visibleContent?.includes('resourceType') ?? true,
        },
        {
          id: 'resourceId',
          label: 'Resource ID',
          visible: preferences?.visibleContent?.includes('resourceId') ?? true,
        },
        { id: 'severity', label: 'Severity', visible: preferences?.visibleContent?.includes('severity') ?? true },
        {
          id: 'securityHubUpdatedAtTime',
          label: 'Security Hub Updated Time',
          visible: preferences?.visibleContent?.includes('securityHubUpdatedAtTime') ?? true,
        },
        {
          id: 'consoleLink',
          label: 'Finding Link',
          visible: preferences?.visibleContent?.includes('consoleLink') ?? true,
        },
        ...(showSuppressed
          ? [
              {
                id: 'suppressed',
                label: 'Suppressed',
                visible: preferences?.visibleContent?.includes('suppressed') ?? true,
              },
            ]
          : []),
      ],
    },
    onConfirm: ({ detail }: { detail: CollectionPreferencesProps.Preferences }) => {
      // Convert contentDisplay array to visibleContent array
      const visibleContent = detail.contentDisplay?.filter((item) => item.visible).map((item) => item.id);

      setPreferences({
        ...preferences,
        visibleContent,
      });
      findingsTablePreferences.save({ visibleContent });
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

  const allColumnDefinitions = useMemo(() => createColumnDefinitions(navigate), [navigate]);

  const columnDefinitions = useMemo(() => {
    if (!preferences?.visibleContent) {
      // Default: show all columns except suppressed
      return allColumnDefinitions.filter((col) => col.id !== 'suppressed');
    }

    return allColumnDefinitions.filter((col) => col.id && preferences.visibleContent?.includes(col.id));
  }, [allColumnDefinitions, preferences?.visibleContent]);

  const handleFilterChange = ({ detail }: { detail: PropertyFilterProps.Query }) => {
    const tokens = [...(detail.tokens || [])];
    const operation = detail.operation || 'and';
    setFilterTokens(tokens);
    setFilterOperation(operation);
    findingsTablePreferences.save({ filterTokens: tokens });
  };

  const handleSortingChange = ({ detail }: { detail: TableProps.SortingState<FindingApiResponse> }) => {
    if (detail.sortingColumn) {
      setSortingColumn(detail.sortingColumn);
    }
    setSortingDescending(detail.isDescending ?? false);
    findingsTablePreferences.save({
      sortingField: detail.sortingColumn?.sortingField,
      sortingDescending: detail.isDescending ?? false,
    });
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
      },
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

  // Single source of truth for the warning Alert, shared by both action
  // handlers. Picks the header to match the outcome and always sets (or clears)
  // the message, so a stale warning never survives an all-success or
  // total-failure result and a batch failure is never mislabeled as "skipped".
  const applyActionWarning = (skippedOrUnresolvedText: string | null, failureText: string | null): void => {
    if (skippedOrUnresolvedText && failureText) {
      setWarningHeader(WARNING_HEADER_SKIPPED_AND_FAILED);
      setWarningMessage(`${skippedOrUnresolvedText} ${failureText}`);
    } else if (failureText) {
      setWarningHeader(WARNING_HEADER_FAILED);
      setWarningMessage(failureText);
    } else if (skippedOrUnresolvedText) {
      setWarningHeader(WARNING_HEADER_SKIPPED);
      setWarningMessage(skippedOrUnresolvedText);
    } else {
      setWarningMessage(null);
    }
  };

  // Generic suppress/unsuppress handler. Takes the selected items directly (rather than
  // reading pendingAction via closure) so findingId/findingType are always sourced from the
  // same items and never go stale.
  const handleSuppressionAction = async (
    actionType: 'Suppress' | 'Unsuppress',
    items: readonly FindingApiResponse[],
  ) => {
    const suppressValue = actionType === 'Suppress';

    const { submittedIds, unresolvedIds, failedIds, errorMessage } = await executeFindingActionInBatches(
      executeAction,
      actionType,
      items,
    );

    if (submittedIds.length > 0) {
      const submittedIdSet = new Set<string>(submittedIds);
      setAllFindings((prevFindings) =>
        prevFindings.map((finding) =>
          submittedIdSet.has(finding.findingId) ? { ...finding, suppressed: suppressValue } : finding,
        ),
      );
    }
    console.log(`Successfully ${actionType}ed ${submittedIds.length} finding(s)`);

    const submittedPlural = submittedIds.length === 1 ? '' : 's';
    const successText = `Successfully ${actionType.toLowerCase()}ed ${submittedIds.length} finding${submittedPlural}`;

    // Suppress/Unsuppress return no unresolvedIds today, so this is null on the
    // common path and shows no warning. A future/edge response is surfaced as a
    // neutral note instead of being silently dropped.
    const unresolvedFindingLabel = unresolvedIds.length === 1 ? 'finding was' : 'findings were';
    const unresolvedNote =
      unresolvedIds.length > 0 ? `${unresolvedIds.length} ${unresolvedFindingLabel} not processed.` : null;

    if (failedIds.length === 0) {
      // Common all-success path: preserve the original single-request message.
      setErrorMessage(null);
      setSuccessMessage(successText);
      applyActionWarning(unresolvedNote, null);
    } else if (submittedIds.length > 0) {
      // Some batches succeeded and some failed: report both.
      setErrorMessage(null);
      setSuccessMessage(successText);
      applyActionWarning(unresolvedNote, buildFailedFindingsMessage(actionType, failedIds.length, errorMessage));
    } else {
      // Every batch failed: match today's failure path text.
      console.error(`Failed to ${actionType} findings`);
      setSuccessMessage(null);
      setErrorMessage(`Failed to ${actionType} findings: ${errorMessage || 'Please try again.'}`);
      applyActionWarning(unresolvedNote, null);
    }
  };

  const handleSuppressAction = async (items: readonly FindingApiResponse[]): Promise<void> => {
    await handleSuppressionAction('Suppress', items);
  };

  const handleUnsuppressAction = async (items: readonly FindingApiResponse[]): Promise<void> => {
    await handleSuppressionAction('Unsuppress', items);
  };

  // Build the "skipped findings" warning (or null when nothing was skipped).
  // Extracted from handleRemediationAction to keep that handler's complexity low.
  const buildSkippedWarning = (
    items: readonly FindingApiResponse[],
    unresolvedIds: string[],
    unresolvedSet: Set<string>,
  ): string | null => {
    if (unresolvedIds.length === 0) return null;
    // Pair each skipped finding's type with its unsupported resource type — e.g.
    // "Inspector.InstanceVulnerability does not support AwsLambdaFunction". Distinct
    // pairs only, so a multi-select of the same unsupported combination reads once.
    const skippedPairs = [
      ...new Set(
        items
          .filter((item) => unresolvedSet.has(item.findingId))
          .map((item) => `${item.findingType} does not support ${item.resourceType}`),
      ),
    ];
    const skipDetail = skippedPairs.length ? ` (${skippedPairs.join('; ')})` : '';
    return `${unresolvedIds.length} finding${unresolvedIds.length === 1 ? ' was' : 's were'} skipped: the resource type is not supported for the selected remediation${skipDetail}.`;
  };

  const handleRemediationAction = async (
    actionType: 'Remediate' | 'RemediateAndGenerateTicket',
    items: readonly FindingApiResponse[],
  ) => {
    // The API skips findings it cannot act on (e.g. an Amazon Inspector
    // Lambda/ECR finding routed to the EC2-only patch remediation) and returns
    // them as unresolvedIds. Only flip the findings that were actually
    // submitted to IN_PROGRESS — leaving a skipped finding as IN_PROGRESS would
    // flicker back to its stored status on the next refresh and hide the fact
    // it was not remediated.
    const { submittedIds, unresolvedIds, failedIds, errorMessage } = await executeFindingActionInBatches(
      executeAction,
      actionType,
      items,
    );
    const unresolvedSet = new Set<string>(unresolvedIds);

    if (submittedIds.length > 0) {
      const submittedIdSet = new Set<string>(submittedIds);
      setAllFindings((prevFindings) =>
        prevFindings.map((finding) =>
          submittedIdSet.has(finding.findingId)
            ? {
                ...finding,
                remediationStatus: 'IN_PROGRESS' as const,
                lastUpdatedTime: new Date().toISOString(),
              }
            : finding,
        ),
      );
    }
    console.log(
      `Successfully initiated ${actionType} for ${submittedIds.length} finding(s); ${unresolvedIds.length} skipped`,
    );

    // Explain why each finding was skipped (finding type vs. unsupported
    // resource type). Both fields come from the selected items mapped back from
    // the API's unresolvedIds, so no extra API field is needed.
    const skippedWarning = buildSkippedWarning(items, unresolvedIds, unresolvedSet);
    const submittedPlural = submittedIds.length === 1 ? '' : 's';
    const successText =
      submittedIds.length > 0
        ? `Successfully sent ${submittedIds.length} finding${submittedPlural} for Remediation`
        : null;

    if (failedIds.length === 0) {
      // Common path: no batch failed. Preserve the original success + skipped
      // warning behavior.
      setErrorMessage(null);
      setSuccessMessage(successText);
      applyActionWarning(skippedWarning, null);
    } else if (submittedIds.length > 0) {
      // Some batches succeeded and some failed: keep the skipped warning (if
      // any) and the batch-failure note so neither is lost.
      setErrorMessage(null);
      setSuccessMessage(successText);
      applyActionWarning(skippedWarning, buildFailedFindingsMessage(actionType, failedIds.length, errorMessage));
    } else {
      // Every batch failed: match today's failure path text.
      console.error(`Failed to execute ${actionType}`);
      setSuccessMessage(null);
      setErrorMessage(`Failed to ${actionType}: ${errorMessage || 'Please try again.'}`);
      applyActionWarning(skippedWarning, null);
    }
  };

  // Handle remediate action
  const handleRemediateAction = async (items: readonly FindingApiResponse[]): Promise<void> => {
    await handleRemediationAction('Remediate', items);
  };

  // Handle remediate and ticket action
  const handleRemediateAndTicketAction = async (items: readonly FindingApiResponse[]): Promise<void> => {
    await handleRemediationAction('RemediateAndGenerateTicket', items);
  };

  // Execute the confirmed action
  const executeConfirmedAction = async () => {
    if (!pendingAction || pendingAction.items.length === 0) return;

    try {
      const { items } = pendingAction;

      switch (pendingAction.type) {
        case 'suppress':
          await handleSuppressAction(items);
          break;
        case 'unsuppress':
          await handleUnsuppressAction(items);
          break;
        case 'remediate':
          await handleRemediateAction(items);
          break;
        case 'remediateAndTicket':
          await handleRemediateAndTicketAction(items);
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
  const getModalContent = (): ModalContent => {
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
        return getRemediationModalContent(pendingAction.items, count);
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
    setWarningMessage(null);
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
            `Partial Export: Exported ${result.totalExported.toLocaleString()} records. ${result.message || ''}`,
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
                <Button onClick={() => navigate('/history')}>View History</Button>
              ) : undefined
            }
          >
            {successMessage}
          </Alert>
        </Box>
      )}

      {warningMessage && (
        <Box margin={{ top: 'xs', bottom: 'xs', horizontal: 'xxxl' }} padding={{ horizontal: 'xxxl' }}>
          <Alert type="warning" dismissible onDismiss={() => setWarningMessage(null)} header={warningHeader}>
            {warningMessage}
          </Alert>
        </Box>
      )}

      {errorMessage && (
        <Box margin={{ top: 'xs', bottom: 'xs', horizontal: 'xxxl' }} padding={{ horizontal: 'xxxl' }}>
          <Alert type="error" dismissible onDismiss={() => setErrorMessage(null)} header="Operation Failed">
            {errorMessage}
          </Alert>
        </Box>
      )}

      {selectedItems.length >= SELECTION_LIMIT && (
        <Box margin={{ top: 'xs', bottom: 'xs', horizontal: 'xxxl' }} padding={{ horizontal: 'xxxl' }}>
          <Alert type="info" header="Selection limit reached">
            You can act on up to {SELECTION_LIMIT} findings at a time from the Web UI. To act on more than{' '}
            {SELECTION_LIMIT} findings, call the API directly instead of using the Web UI. See the Implementation Guide
            for instructions.
          </Alert>
        </Box>
      )}

      {/* Header Section */}
      <Header
        variant="h1"
        counter={`(${findings.length}${hasMoreData ? '+' : ''})`}
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            <Button iconName="refresh" loading={isLoading} onClick={handleRefresh} ariaLabel="Refresh findings" />
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
              removeTokenButtonAriaLabel: (token) =>
                `Remove token ${token.propertyKey} ${token.operator} ${token.value}`,
              enteredTextLabel: (text) => `Use: "${text}"`,
            }}
            expandToViewport
          />
        </div>
        <CollectionPreferences {...collectionPreferencesProps} />
      </div>

      <Box padding={{ vertical: 's' }}>
        <Toggle
          onChange={({ detail }) => {
            const newShowSuppressed = detail.checked;
            setShowSuppressed(newShowSuppressed);

            const currentColumns = preferences?.visibleContent || [];
            const newVisibleContent = newShowSuppressed
              ? [...new Set([...currentColumns, 'suppressed'])]
              : currentColumns.filter((col) => col !== 'suppressed');

            setPreferences({
              ...preferences,
              visibleContent: newVisibleContent,
            });

            findingsTablePreferences.save({
              showSuppressed: newShowSuppressed,
              visibleContent: newVisibleContent,
            });
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
          onSelectionChange={({ detail }) =>
            setSelectedItems(limitFindingSelection(detail.selectedItems, findings, SELECTION_LIMIT))
          }
          sortingColumn={sortingColumn}
          sortingDescending={sortingDescending}
          onSortingChange={handleSortingChange}
          stickyHeader
          stripedRows={preferences?.stripedRows ?? false}
          contentDensity={preferences?.contentDensity ?? 'comfortable'}
          wrapLines={preferences?.wrapLines ?? true}
          variant="full-page"
          selectionType="multi"
          isItemDisabled={(item) => isRowSelectionDisabled(item, selectedItems, SELECTION_LIMIT)}
          ariaLabels={{
            selectionGroupLabel: 'Items selection',
            tableLabel: 'Findings table',
            allItemsSelectionLabel: ({ selectedItems }) =>
              `${selectedItems.length} ${selectedItems.length === 1 ? 'item' : 'items'} selected`,
            itemSelectionLabel: ({ selectedItems }, item) => {
              const isItemSelected = selectedItems.filter((i) => i.findingId === item.findingId).length;
              return `${item.findingDescription} is ${isItemSelected ? '' : 'not '}selected`;
            },
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
              <span>Loading more findings...</span>
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
                <Button variant="primary" onClick={executeConfirmedAction} loading={isExecutingAction}>
                  {getModalContent().actionButton}
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween size="m">
            <Box>{getModalContent().message}</Box>
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
