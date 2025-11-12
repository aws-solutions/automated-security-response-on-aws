// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FindingApiResponse, RemediationHistoryApiResponse } from '@data-models';
import { delay, http, HttpResponse } from 'msw';
import { generateTestFindings, generateTestRemediations } from '../__tests__/test-data-factory';
import { ApiEndpoints } from '../store/solutionApi.ts';

// This file contains msw mocks of ASR's API endpoints.
// the mocks can be used for unit tests, as well as local development as long as no backend is available

/**
 * Return a 200 OK http response with the given payload.
 * Delays the response by 200ms to simulate realistic latency and allow
 * to test a loading spinner etc on the UI.
 */
export const ok = async (payload: object | object[], delayMilliseconds: number = 200) => {
  await delay(delayMilliseconds);
  return HttpResponse.json(payload, {
    status: 200,
    headers: [['Access-Control-Allow-Origin', '*']],
  });
};

const badRequest = async (payload: object | object[], delayMilliseconds: number = 200) => {
  await delay(delayMilliseconds);
  return HttpResponse.json(payload, {
    status: 400,
    headers: [['Access-Control-Allow-Origin', '*']],
  });
};

export const postFindingsHandler = (apiUrl: string) =>
  http.post(apiUrl + ApiEndpoints.FINDINGS, async ({ request }) => {
    const searchRequest = (await request.json()) as any;
    console.log('MSW: Handling POST /findings request:', searchRequest);

    let filteredFindings = [...mockFindings];

    if (searchRequest.Filters?.StringFilters) {
      searchRequest.Filters.StringFilters.forEach((filter: any) => {
        filteredFindings = filteredFindings.filter((finding: FindingApiResponse) => {
          const fieldValue = (finding as any)[filter.FieldName];
          if (!fieldValue) return false;

          const value = fieldValue.toString().toLowerCase();
          const filterValue = filter.Filter.Value.toLowerCase();

          switch (filter.Filter.Comparison) {
            case 'EQUALS':
              return value === filterValue;
            case 'NOT_EQUALS':
              return value !== filterValue;
            case 'CONTAINS':
              return value.includes(filterValue);
            case 'NOT_CONTAINS':
              return !value.includes(filterValue);
            default:
              return true;
          }
        });
      });
    }

    const maxResults = searchRequest.MaxResults || 20;
    let startIndex = 0;

    if (searchRequest.NextToken) {
      try {
        const decodedToken = atob(searchRequest.NextToken);
        const tokenData = JSON.parse(decodedToken);

        if (tokenData.id && tokenData.securityHubUpdatedAtTime) {
          const lastItemIndex = filteredFindings.findIndex((f) => f.findingId === tokenData.id);
          startIndex = lastItemIndex >= 0 ? lastItemIndex + 1 : 0;
        } else if (tokenData.startIndex !== undefined) {
          startIndex = tokenData.startIndex;
        }

        console.log('MSW: Parsed NextToken:', { tokenData, startIndex });
      } catch (error) {
        console.warn('MSW: Invalid NextToken, starting from beginning:', error);
        startIndex = 0;
      }
    }

    const endIndex = startIndex + maxResults;
    const paginatedFindings = filteredFindings.slice(startIndex, endIndex);

    let nextToken: string | undefined;
    if (endIndex < filteredFindings.length) {
      const lastItem = paginatedFindings[paginatedFindings.length - 1];

      const lastEvaluatedKey = {
        id: lastItem.findingId,
        securityHubUpdatedAtTime: lastItem.securityHubUpdatedAtTime,
        FindingType: lastItem.findingType,
        FindingId: lastItem.findingId,
        'securityHubUpdatedAtTime#findingId': `${lastItem.securityHubUpdatedAtTime}#${lastItem.findingId}`,
        FINDING_CONSTANT: 'finding',
      };

      nextToken = btoa(JSON.stringify(lastEvaluatedKey));
    }

    return ok({
      Findings: paginatedFindings,
      NextToken: nextToken,
    });
  });

export const putFindingsHandler = (apiUrl: string) =>
  http.put(`${apiUrl + ApiEndpoints.FINDINGS}/{id}`, async ({ request }) => {
    const findingUpdateRequest = (await request.json()) as any;
    return ok({ id: window.crypto.randomUUID(), ...findingUpdateRequest });
  });

export const getRemediationsHandler = (apiUrl: string) =>
  http.get(apiUrl + ApiEndpoints.REMEDIATIONS, () => {
    return ok(mockRemediations);
  });

export const postRemediationHandler = (apiUrl: string) =>
  http.put(apiUrl + ApiEndpoints.REMEDIATIONS, async ({ request }) => {
    const remediationCreateRequest = (await request.json()) as any;
    return ok({ id: window.crypto.randomUUID(), ...remediationCreateRequest });
  });

export const postRemediationsSearchHandler = (apiUrl: string) =>
  http.post(apiUrl + ApiEndpoints.REMEDIATIONS, async ({ request }) => {
    const searchRequest = (await request.json()) as any;
    console.log('MSW: Handling POST /remediations request:', searchRequest);

    let filteredRemediations = [...mockRemediations];

    if (searchRequest.Filters?.CompositeFilters) {
      searchRequest.Filters.CompositeFilters.forEach((compositeFilter: any) => {
        if (compositeFilter.StringFilters) {
          compositeFilter.StringFilters.forEach((filter: any) => {
            filteredRemediations = filteredRemediations.filter((remediation: RemediationHistoryApiResponse) => {
              const fieldValue = (remediation as any)[filter.FieldName];
              if (!fieldValue) return false;

              const value = fieldValue.toString().toLowerCase();
              const filterValue = filter.Filter.Value.toLowerCase();

              switch (filter.Filter.Comparison) {
                case 'EQUALS':
                  return value === filterValue;
                case 'NOT_EQUALS':
                  return value !== filterValue;
                case 'CONTAINS':
                  return value.includes(filterValue);
                case 'NOT_CONTAINS':
                  return !value.includes(filterValue);
                default:
                  return true;
              }
            });
          });
        }
      });
    }

    if (searchRequest.SortCriteria && searchRequest.SortCriteria.length > 0) {
      const sortCriteria = searchRequest.SortCriteria[0];
      const sortField = sortCriteria.Field;
      const sortOrder = sortCriteria.SortOrder;

      filteredRemediations.sort((a, b) => {
        const aValue = (a as any)[sortField];
        const bValue = (b as any)[sortField];

        let comparison = 0;
        if (aValue < bValue) comparison = -1;
        if (aValue > bValue) comparison = 1;

        return sortOrder === 'desc' ? -comparison : comparison;
      });
    }

    const maxResults = searchRequest.MaxResults || 20;
    let startIndex = 0;

    if (searchRequest.NextToken) {
      try {
        const decodedToken = atob(searchRequest.NextToken);
        const tokenData = JSON.parse(decodedToken);

        if (tokenData.id && tokenData.lastUpdatedTime) {
          const lastItemIndex = filteredRemediations.findIndex((r) => r.executionId === tokenData.id);
          startIndex = lastItemIndex >= 0 ? lastItemIndex + 1 : 0;
        } else if (tokenData.startIndex !== undefined) {
          startIndex = tokenData.startIndex;
        }

        console.log('MSW: Parsed NextToken:', { tokenData, startIndex });
      } catch (error) {
        console.warn('MSW: Invalid NextToken, starting from beginning:', error);
        startIndex = 0;
      }
    }

    const endIndex = startIndex + maxResults;
    const paginatedRemediations = filteredRemediations.slice(startIndex, endIndex);

    let nextToken: string | undefined;
    if (endIndex < filteredRemediations.length) {
      const lastItem = paginatedRemediations[paginatedRemediations.length - 1];

      const lastEvaluatedKey = {
        executionId: lastItem.executionId,
        lastUpdatedTime: lastItem.lastUpdatedTime,
        findingId: lastItem.findingId,
        'lastUpdatedTime#findingId': `${lastItem.lastUpdatedTime}#${lastItem.findingId}`,
        REMEDIATION_CONSTANT: 'remediation',
      };

      nextToken = btoa(JSON.stringify(lastEvaluatedKey));
    }

    return ok({
      Remediations: paginatedRemediations,
      NextToken: nextToken,
    });
  });

export const getUserSelfHandler = (apiUrl: string) =>
  http.get(apiUrl + ApiEndpoints.USERS, () => {
    return ok({ alias: 'john_doe' });
  });

export const getUsersHandler = (apiUrl: string) =>
  http.get(apiUrl + ApiEndpoints.USERS, () => {
    return ok([
      {
        email: 'operator1@example.com',
        accountIds: ['123456789012', '123456789013'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        userStatus: 'ACTIVE',
      },
      {
        email: 'delegated1@example.com',
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        userStatus: 'PENDING',
      },
    ]);
  });

export const getUserByIdHandler = (apiUrl: string) =>
  http.get(`${apiUrl + ApiEndpoints.USERS}/:id`, ({ params }) => {
    const { id } = params;
    const decodedId = decodeURIComponent(id as string);
    const mockUsers = {
      'operator1@example.com': {
        email: 'operator1@example.com',
        type: 'account-operator',
        accountIds: ['123456789012', '123456789013'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Confirmed',
      },
      'delegated1@example.com': {
        email: 'delegated1@example.com',
        type: 'delegated-admin',
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Invited',
      },
      'admin@example.com': {
        email: 'admin@example.com',
        type: 'admin',
        invitedBy: 'system@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Confirmed',
      },
    };

    const user = mockUsers[decodedId as keyof typeof mockUsers];
    return user ? ok(user) : badRequest({ error: 'User not found' });
  });

/**
 * @param apiUrl the base url for http requests. only requests to this base url will be intercepted and handled by mock-service-worker.
 */
export const handlers = (apiUrl: string) => [
  getUserSelfHandler(apiUrl),
  getUsersHandler(apiUrl),
  getUserByIdHandler(apiUrl),
  getRemediationsHandler(apiUrl),
  postRemediationHandler(apiUrl),
  postRemediationsSearchHandler(apiUrl),
  postFindingsHandler(apiUrl),
  putFindingsHandler(apiUrl),
];

export const mockRemediations: RemediationHistoryApiResponse[] = generateTestRemediations(100);

// for each org, generate between 5 and 10 portfolios
export const mockFindings: FindingApiResponse[] = generateTestFindings(100);
