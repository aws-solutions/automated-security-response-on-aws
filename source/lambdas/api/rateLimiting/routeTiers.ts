// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical mapping of API routes to rate-limit tiers.
 *
 * Used to classify each request into a tier for the write-anomaly alarms and
 * metrics (see `writeMetrics.ts`).
 *
 * The route set here mirrors the `routes` table in `handlers/apiHandler.ts`.
 * Keep the two in sync: every routable (method, path) must have a tier so a
 * request can never fall through unclassified.
 *
 * Tiers (highest sensitivity first):
 *  - `critical`        : state changes with the largest blast radius — disabling
 *                        controls, deleting filters, user lifecycle, finding
 *                        actions (which trigger remediations), disabling or
 *                        deleting notifications.
 *  - `sensitiveWrite`  : configuration writes that are security-relevant but
 *                        lower blast radius than `critical`.
 *  - `read`            : everything else — reads, searches, exports, and test
 *                        sends; the catch-all for requests that are not
 *                        security-relevant writes.
 */
export type RateLimitTierName = 'critical' | 'sensitiveWrite' | 'read';

/** HTTP methods the API router can register; narrowed so typos fail to compile. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface RouteDefinition {
  /** HTTP method, uppercase (e.g. 'POST'). */
  readonly method: HttpMethod;
  /**
   * Path template using `{param}` placeholders for path parameters, matching
   * the templates registered in `apiHandler.ts` (e.g. '/filters/{filterId}').
   */
  readonly pathTemplate: string;
  readonly tier: RateLimitTierName;
}

export const RATE_LIMIT_ROUTES: readonly RouteDefinition[] = [
  // ─── critical ────────────────────────────────────────────────────────────
  { method: 'POST', pathTemplate: '/controls/bulk-edit', tier: 'critical' },
  { method: 'DELETE', pathTemplate: '/filters/{filterId}', tier: 'critical' },
  { method: 'POST', pathTemplate: '/users', tier: 'critical' },
  { method: 'DELETE', pathTemplate: '/users/{id}', tier: 'critical' },
  { method: 'POST', pathTemplate: '/findings/action', tier: 'critical' },
  { method: 'DELETE', pathTemplate: '/notifications/{id}', tier: 'critical' },
  { method: 'PATCH', pathTemplate: '/notifications/{id}', tier: 'critical' },

  // ─── sensitiveWrite ──────────────────────────────────────────────────────
  { method: 'POST', pathTemplate: '/filters', tier: 'sensitiveWrite' },
  { method: 'PUT', pathTemplate: '/filters/{filterId}', tier: 'sensitiveWrite' },
  { method: 'PUT', pathTemplate: '/users/{id}', tier: 'sensitiveWrite' },
  { method: 'POST', pathTemplate: '/notifications', tier: 'sensitiveWrite' },
  { method: 'PUT', pathTemplate: '/notifications/{id}', tier: 'sensitiveWrite' },

  // ─── read ────────────────────────────────────────────────────────────────
  { method: 'GET', pathTemplate: '/controls', tier: 'read' },
  { method: 'GET', pathTemplate: '/filters', tier: 'read' },
  { method: 'GET', pathTemplate: '/users', tier: 'read' },
  { method: 'POST', pathTemplate: '/findings', tier: 'read' },
  { method: 'POST', pathTemplate: '/remediations', tier: 'read' },
  { method: 'GET', pathTemplate: '/notifications', tier: 'read' },
  { method: 'GET', pathTemplate: '/notifications/{id}', tier: 'read' },
  { method: 'GET', pathTemplate: '/notifications/{id}/subscriptions', tier: 'read' },
  { method: 'GET', pathTemplate: '/iac/{findingId}', tier: 'read' },
  { method: 'POST', pathTemplate: '/findings/export', tier: 'read' },
  { method: 'POST', pathTemplate: '/export', tier: 'read' },
  { method: 'POST', pathTemplate: '/notifications/{id}/subscriptions/resend', tier: 'read' },
  { method: 'POST', pathTemplate: '/notifications/{id}/test', tier: 'read' },
];

/**
 * Tiers whose routes are security-relevant mutating writes. These are the
 * routes the WAF sensitive-write rate-based rule targets (see
 * `buildRateLimitRules` in `lib/webui/api-construct.ts`).
 */
export const SENSITIVE_WRITE_TIERS: ReadonlySet<RateLimitTierName> = new Set<RateLimitTierName>([
  'critical',
  'sensitiveWrite',
]);

/**
 * The subset of {@link RATE_LIMIT_ROUTES} in the `critical` and
 * `sensitiveWrite` tiers. This is the single source of truth for the WAF
 * sensitive-write scope-down: the WAF rule derives its path/method matches from
 * this list rather than maintaining its own copy, so the two cannot drift (a
 * `read`-tier route sharing a prefix — e.g. `POST /notifications/{id}/test` —
 * is excluded here and therefore never swept into the sensitive-write limit).
 */
export const SENSITIVE_WRITE_ROUTES: readonly RouteDefinition[] = RATE_LIMIT_ROUTES.filter((route) =>
  SENSITIVE_WRITE_TIERS.has(route.tier),
);

/**
 * Returns true when `path` matches `template`, treating any `{param}` segment
 * in the template as a single-segment wildcard. Matching is exact on segment
 * count and on every literal segment, so overlapping prefixes (e.g.
 * '/notifications/{id}' vs '/notifications/{id}/test') never collide.
 */
function pathMatchesTemplate(path: string, template: string): boolean {
  const pathSegments = path.split('/').filter(Boolean);
  const templateSegments = template.split('/').filter(Boolean);

  if (pathSegments.length !== templateSegments.length) {
    return false;
  }

  return templateSegments.every((segment, index) => segment.startsWith('{') || segment === pathSegments[index]);
}

/**
 * Classifies a request into a rate-limit tier by matching its method and path
 * against {@link RATE_LIMIT_ROUTES}. `path` must already be normalized to the
 * resource path (no API Gateway stage prefix). Returns `undefined` when no
 * route matches (e.g. CORS preflight or an unknown path), in which case callers
 * should treat the request as unclassified and skip per-tier metric emission.
 */
export function classifyRoute(method: string, path: string): RateLimitTierName | undefined {
  const normalizedMethod = method.toUpperCase();
  const match = RATE_LIMIT_ROUTES.find(
    (route) => route.method === normalizedMethod && pathMatchesTemplate(path, route.pathTemplate),
  );
  return match?.tier;
}
