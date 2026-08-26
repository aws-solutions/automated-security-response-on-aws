// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  classifyRoute,
  RATE_LIMIT_ROUTES,
  RouteDefinition,
  SENSITIVE_WRITE_ROUTES,
} from '../../rateLimiting/routeTiers';
import { routes as handlerRoutes } from '../../handlers/apiHandler';

describe('routeTiers', () => {
  describe('classifyRoute', () => {
    it('classifies representative routes from every tier, including templated paths', () => {
      // ARRANGE: one concrete request per tier, using real-looking path params
      const findingId = encodeURIComponent('arn:aws:securityhub:us-east-1:111111111111:finding/abc');
      const uuid = 'aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee';

      // ACT & ASSERT: each request maps to its expected tier
      expect(classifyRoute('POST', '/controls/bulk-edit')).toBe('critical');
      expect(classifyRoute('DELETE', `/filters/${uuid}`)).toBe('critical');
      expect(classifyRoute('POST', '/findings/action')).toBe('critical');
      expect(classifyRoute('DELETE', `/notifications/${uuid}`)).toBe('critical');
      expect(classifyRoute('PATCH', `/notifications/${uuid}`)).toBe('critical');

      expect(classifyRoute('POST', '/filters')).toBe('sensitiveWrite');
      expect(classifyRoute('PUT', `/filters/${uuid}`)).toBe('sensitiveWrite');
      expect(classifyRoute('PUT', `/users/${uuid}`)).toBe('sensitiveWrite');

      expect(classifyRoute('POST', '/findings/export')).toBe('read');
      expect(classifyRoute('POST', '/export')).toBe('read');
      expect(classifyRoute('POST', `/notifications/${uuid}/subscriptions/resend`)).toBe('read');
      expect(classifyRoute('POST', `/notifications/${uuid}/test`)).toBe('read');

      expect(classifyRoute('GET', '/controls')).toBe('read');
      expect(classifyRoute('POST', '/findings')).toBe('read');
      expect(classifyRoute('POST', '/remediations')).toBe('read');
      expect(classifyRoute('GET', `/notifications/${uuid}`)).toBe('read');
      expect(classifyRoute('GET', `/notifications/${uuid}/subscriptions`)).toBe('read');
      expect(classifyRoute('GET', `/iac/${findingId}`)).toBe('read');
    });

    it('disambiguates overlapping notification prefixes by segment count and literals', () => {
      // ARRANGE: paths sharing the /notifications/{id} prefix at different segment depths
      const uuid = 'aaaaaaaa-bbbb-4ccc-addd-eeeeeeeeeeee';

      // ACT & ASSERT: each path resolves to its own route by segment count and literals
      expect(classifyRoute('GET', `/notifications/${uuid}`)).toBe('read');
      expect(classifyRoute('DELETE', `/notifications/${uuid}`)).toBe('critical');
      expect(classifyRoute('POST', `/notifications/${uuid}/test`)).toBe('read');
      expect(classifyRoute('POST', `/notifications/${uuid}/subscriptions/resend`)).toBe('read');
    });

    it('matches the HTTP method case-insensitively', () => {
      // ARRANGE / ACT / ASSERT: lowercase method still classifies
      expect(classifyRoute('post', '/controls/bulk-edit')).toBe('critical');
      expect(classifyRoute('get', '/controls')).toBe('read');
    });

    it('returns undefined for unmatched method, unknown path, and preflight', () => {
      // ARRANGE / ACT / ASSERT: nothing should fall through to a tier by accident
      expect(classifyRoute('OPTIONS', '/controls')).toBeUndefined(); // CORS preflight
      expect(classifyRoute('GET', '/controls/bulk-edit')).toBeUndefined(); // wrong method
      expect(classifyRoute('GET', '/does-not-exist')).toBeUndefined(); // unknown path
      expect(classifyRoute('POST', '/controls')).toBeUndefined(); // method not registered
    });
  });

  describe('route table integrity', () => {
    it('has no duplicate method+path entries and only known tiers', () => {
      // ARRANGE
      const knownTiers = new Set(['critical', 'sensitiveWrite', 'read']);
      const seen = new Set<string>();

      // ACT / ASSERT
      RATE_LIMIT_ROUTES.forEach((route: RouteDefinition) => {
        const key = `${route.method} ${route.pathTemplate}`;
        expect(seen.has(key)).toBe(false);
        seen.add(key);
        expect(knownTiers.has(route.tier)).toBe(true);
      });
    });

    it('stays in sync with the handler route table (every route is tiered, and vice versa)', () => {
      // ARRANGE: the (method, path) set the router actually serves vs. the tier map
      const handlerKeys = new Set(handlerRoutes.map((route) => `${route.method} ${route.path}`));
      const tierKeys = new Set(RATE_LIMIT_ROUTES.map((route) => `${route.method} ${route.pathTemplate}`));

      // ACT
      const untiered = [...handlerKeys].filter((key) => !tierKeys.has(key));
      const orphaned = [...tierKeys].filter((key) => !handlerKeys.has(key));

      // ASSERT: neither table drifts from the other — a new endpoint must appear in both
      expect(untiered).toEqual([]);
      expect(orphaned).toEqual([]);
    });
  });

  describe('SENSITIVE_WRITE_ROUTES', () => {
    it('contains exactly the critical and sensitiveWrite tiers and excludes reads', () => {
      // ARRANGE: the routes that should and should not back the WAF sensitive-write rule
      const expectedSensitive = RATE_LIMIT_ROUTES.filter(
        (route) => route.tier === 'critical' || route.tier === 'sensitiveWrite',
      );
      const sensitiveKeys = new Set(SENSITIVE_WRITE_ROUTES.map((route) => `${route.method} ${route.pathTemplate}`));

      // ACT / ASSERT: every sensitive route is present, and no `read` route leaks in
      expect(SENSITIVE_WRITE_ROUTES).toHaveLength(expectedSensitive.length);
      expect(SENSITIVE_WRITE_ROUTES.every((route) => route.tier !== 'read')).toBe(true);

      // ASSERT: mutating reads sharing a sensitive prefix are deliberately excluded,
      // so the WAF scope-down derived from this list cannot sweep them in.
      expect(sensitiveKeys.has('POST /notifications/{id}/test')).toBe(false);
      expect(sensitiveKeys.has('POST /notifications/{id}/subscriptions/resend')).toBe(false);
      expect(sensitiveKeys.has('POST /notifications')).toBe(true);
      expect(sensitiveKeys.has('DELETE /notifications/{id}')).toBe(true);
    });
  });
});
