// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { BaseSearchService } from '../../services/baseSearchService';
import { AuthenticatedUser } from '../../services/authorization';
import { BadRequestError } from '../../../common/utils/httpErrors';

// Criteria conversion publishes usage metrics, which would otherwise reach SSM and the
// metrics endpoint. The filter-field rules under test do not depend on it.
jest.mock('../../../common/utils/metricsUtils', () => ({ sendMetrics: jest.fn().mockResolvedValue(undefined) }));

type TestStringFilter = {
  FieldName?: string;
  Filter?: { Value?: string; Comparison?: 'EQUALS' | 'NOT_CONTAINS' };
};

interface TestRequest {
  Filters?: {
    StringFilters?: TestStringFilter[];
    CompositeFilters?: Array<{ Operator: 'AND' | 'OR'; StringFilters: TestStringFilter[] }>;
    CompositeOperator?: 'AND' | 'OR';
  };
}

/**
 * Exposes the protected account-filtering hook. The hook rewrites the request
 * object only, so it needs no DynamoDB access to exercise.
 */
class TestSearchService extends BaseSearchService {
  constructor() {
    super(new Logger({ serviceName: 'test' }));
  }

  applyAccountFiltering(user: AuthenticatedUser, request: TestRequest): TestRequest {
    return this.applyAccountFilteringForAccountOperators(user, request);
  }

  convertRemediations(request: TestRequest) {
    return this.convertToSearchCriteria(request, 'Remediations');
  }

  convertFindings(request: TestRequest) {
    return this.convertToSearchCriteria(request, 'Findings');
  }
}

const operator = (authorizedAccounts: string[]): AuthenticatedUser => ({
  username: 'op',
  email: 'op@example.com',
  groups: ['AccountOperatorGroup'],
  authorizedAccounts,
});

/** Every accountId value the request's composite filters would match on. */
const ceilingAccounts = (request: TestRequest): string[] =>
  (request.Filters?.CompositeFilters ?? [])
    .flatMap((composite) => composite.StringFilters ?? [])
    .filter((stringFilter) => stringFilter.FieldName === 'accountId')
    .map((stringFilter) => stringFilter.Filter?.Value ?? '');

describe('applyAccountFilteringForAccountOperators', () => {
  let service: TestSearchService;

  beforeEach(() => {
    service = new TestSearchService();
  });

  it('leaves the request untouched for a user with no authorized accounts', () => {
    const admin: AuthenticatedUser = { username: 'a', email: 'a@example.com', groups: ['AdminGroup'] };
    const request: TestRequest = { Filters: { StringFilters: [{ FieldName: 'severity', Filter: { Value: 'HIGH' } }] } };

    expect(service.applyAccountFiltering(admin, request)).toBe(request);
  });

  it('composes the authorized accounts onto a request that carries no account filter', () => {
    const result = service.applyAccountFiltering(operator(['111122223333']), {});

    expect(ceilingAccounts(result)).toEqual(['111122223333']);
    expect(result.Filters?.CompositeOperator).toBe('AND');
  });

  it('leaves a caller root-level accountId EQUALS filter alone rather than adding the ceiling', () => {
    // Appending the ceiling here would widen the scope, not narrow it: the
    // repository combines filters on one field with OR. It would also cost the
    // accountId index, which needs a single EQUALS filter on the field. The
    // handler has already authorized this account against the operator's set.
    const request: TestRequest = {
      Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Value: '111122223333', Comparison: 'EQUALS' } }] },
    };

    expect(service.applyAccountFiltering(operator(['111122223333']), request)).toBe(request);
  });

  it('leaves a caller composite accountId EQUALS filter alone rather than adding the ceiling', () => {
    const request: TestRequest = {
      Filters: {
        CompositeFilters: [
          {
            Operator: 'OR',
            StringFilters: [{ FieldName: 'accountId', Filter: { Value: '111122223333', Comparison: 'EQUALS' } }],
          },
        ],
      },
    };

    expect(service.applyAccountFiltering(operator(['111122223333']), request)).toBe(request);
  });

  it('composes the ceiling when an accountId filter carries no comparison', () => {
    // Such a filter is dropped when the request is converted to search criteria,
    // so treating it as a caller-supplied scope would leave the query with no
    // account scope at all.
    const request: TestRequest = {
      Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Value: '999988887777' } }] },
    };

    const result = service.applyAccountFiltering(operator(['111122223333']), request);

    expect(ceilingAccounts(result)).toEqual(['111122223333']);
    expect(result.Filters?.CompositeOperator).toBe('AND');
  });

  it('composes the ceiling when an accountId filter carries no value', () => {
    const request: TestRequest = {
      Filters: { StringFilters: [{ FieldName: 'accountId', Filter: { Comparison: 'EQUALS' } }] },
    };

    const result = service.applyAccountFiltering(operator(['111122223333']), request);

    expect(ceilingAccounts(result)).toEqual(['111122223333']);
    expect(result.Filters?.CompositeOperator).toBe('AND');
  });
});

describe('convertToSearchCriteria filter-field validation', () => {
  let service: TestSearchService;

  beforeEach(() => {
    service = new TestSearchService();
  });

  const filterOn = (fieldName: string, comparison: 'EQUALS' | 'NOT_CONTAINS' = 'EQUALS'): TestRequest => ({
    Filters: { StringFilters: [{ FieldName: fieldName, Filter: { Value: 'anything', Comparison: comparison } }] },
  });

  it('rejects a field name the store has no attribute for', async () => {
    // ControlId reads like a real field but is not one: the control lives in
    // findingType as security-control/<control>. Passed through, it became a
    // FilterExpression over a non-existent attribute and returned an empty page
    // with HTTP 200, which is indistinguishable from "no remediations".
    await expect(service.convertRemediations(filterOn('ControlId'))).rejects.toThrow(BadRequestError);
  });

  it('names the offending field and the supported ones so the caller can correct the request', async () => {
    await expect(service.convertRemediations(filterOn('ControlId'))).rejects.toThrow(
      /Unsupported filter field\(s\) for Remediations: ControlId\..*findingType/,
    );
  });

  it('rejects an unsupported field under NOT_CONTAINS, which used to drop the filter entirely', async () => {
    // contains() is false for an attribute that does not exist, so its negation held
    // for every item: the caller silently got a wider answer than they asked for.
    await expect(service.convertRemediations(filterOn('ControlId', 'NOT_CONTAINS'))).rejects.toThrow(BadRequestError);
  });

  it('rejects a field name that differs only in casing', async () => {
    // accountId vs AccountId are separate FilterExpression groups downstream, so the
    // mis-cased one never narrowed anything. It is also the casing that decides
    // whether the account ceiling is injected, so silence here is doubly misleading.
    await expect(service.convertRemediations(filterOn('AccountId'))).rejects.toThrow(BadRequestError);
  });

  it('rejects a field name from inside a composite filter', async () => {
    const request: TestRequest = {
      Filters: {
        CompositeFilters: [{ Operator: 'AND', StringFilters: [{ FieldName: 'ControlId', Filter: { Value: 'S3.1' } }] }],
      },
    };

    await expect(service.convertRemediations(request)).rejects.toThrow(BadRequestError);
  });

  it('rejects a Findings-only field on a Remediations search', async () => {
    await expect(service.convertRemediations(filterOn('suppressed'))).rejects.toThrow(BadRequestError);
    await expect(service.convertFindings(filterOn('suppressed'))).resolves.toBeDefined();
  });

  it('rejects a Remediations-only field on a Findings search', async () => {
    await expect(service.convertFindings(filterOn('ssmExecutionId'))).rejects.toThrow(BadRequestError);
    await expect(service.convertRemediations(filterOn('ssmExecutionId'))).resolves.toBeDefined();
  });

  it('accepts the fields the WebUI filters on', async () => {
    for (const fieldName of ['findingType', 'accountId', 'remediationStatus', 'findingId', 'resourceId', 'severity']) {
      await expect(service.convertRemediations(filterOn(fieldName))).resolves.toBeDefined();
    }
  });

  it('accepts resourceType in any casing and normalizes it to the searched attribute', async () => {
    const criteria = await service.convertRemediations(filterOn('ResourceType'));

    expect(criteria.filters.map((filter) => filter.fieldName)).toEqual(['resourceTypeNormalized']);
  });

  it('leaves a filter with no field name to conversion, which drops it', async () => {
    // The WebUI emits an empty FieldName for a token carrying no property key.
    // Rejecting that request would be a regression.
    const request: TestRequest = { Filters: { StringFilters: [{ FieldName: '', Filter: { Value: 'x' } }] } };

    const criteria = await service.convertRemediations(request);

    expect(criteria.filters).toEqual([]);
  });
});
