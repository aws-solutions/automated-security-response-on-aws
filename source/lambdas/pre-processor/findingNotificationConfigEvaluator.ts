// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import {
  ConfigId,
  NormalizedFinding,
  NotificationConfigurationItem,
  NOTIFICATION_CACHE_TTL_MS,
} from '@asr/data-models';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { Clock } from '../common/utils/clock';
import { LambdaCache } from '../common/utils/lambdaCache';
import {
  passesAccountScopeFilter,
  passesControlFilter,
  passesSeverityFilter,
} from '../common/utils/notificationFilters';
import { computeRemediationDueBy, isEnforcementEnabledConfig } from '../common/utils/remediationDeadline';
import { ResourceFilterEvaluator } from './ResourceFilterEvaluator';

export interface EligibilityResult {
  isEligible: boolean;
  remediationDueBy?: string; // ISO-8601 timestamp
  matchingConfigIds: ConfigId[]; // config IDs that contributed
}

/**
 * Metric-enrichment flags derived from a finding's match against finding-type
 * notification configurations, alongside the deadline enforcement eligibility.
 * Persisted on the finding and read back when the successful-remediation metric
 * is published (to correlate Mean Time To Remediate with notification/deadline
 * configuration).
 */
export interface FindingConfigEvaluation {
  /**
   * True when at least one enabled finding-type config matches this finding on
   * the full delivery scope the dispatcher applies: account, severity, control,
   * and resource filters. Reflects whether the customer would be notified.
   */
  hasNotificationsEnabled: boolean;
  /**
   * True when at least one config that matched the full delivery scope has
   * `includeRemediationDeadline` enabled — i.e. the customer has configured a
   * remediation deadline (not necessarily enforced) for this finding.
   */
  hasDeadlineConfigured: boolean;
  /** Deadline enforcement eligibility (enforcement-enabled configs only). */
  enforcement: EligibilityResult;
}

/**
 * A `FindingConfigEvaluation` representing "no matching configuration": notifications and
 * deadline flags off, and no enforcement eligibility. Used by the ingestion handlers as the
 * safe default when evaluation is skipped or fails, so ingestion always proceeds.
 */
export function emptyFindingConfigEvaluation(): FindingConfigEvaluation {
  return {
    hasNotificationsEnabled: false,
    hasDeadlineConfigured: false,
    enforcement: { isEligible: false, matchingConfigIds: [] },
  };
}

const FINDING_CONFIGS_CACHE_KEY = 'finding-configs';

/**
 * Evaluates a newly ingested finding against enabled finding-type notification
 * configurations in a single pass, producing both:
 *  - deadline enforcement eligibility (`remediationDueBy` when the finding
 *    matches an enforcement-enabled config's control, severity, and resource
 *    filters; shortest deadline wins, all matching config IDs recorded), and
 *  - metric-enrichment flags describing whether notifications and remediation
 *    deadlines are configured for the finding (full delivery scope, including
 *    account scope).
 *
 * Resource filters — the only per-config Organizations/DynamoDB cost — are
 * evaluated once per config and reused for both outputs.
 */
export class FindingNotificationConfigEvaluator {
  private readonly findingConfigsCache: LambdaCache<NotificationConfigurationItem[]>;

  constructor(
    private readonly notificationConfigurationRepository: NotificationConfigurationRepository,
    private readonly resourceFilterEvaluator: ResourceFilterEvaluator,
    private readonly clock: Clock,
    private readonly logger: Logger,
  ) {
    this.findingConfigsCache = new LambdaCache<NotificationConfigurationItem[]>({
      ttlMs: NOTIFICATION_CACHE_TTL_MS,
      fetchFn: () => this.loadFindingConfigs(),
      clock,
    });
  }

  /**
   * Single-pass evaluation of the finding against every enabled finding-type
   * config. Each config's filters are checked once; the result feeds both the
   * metric-enrichment flags and the enforcement eligibility.
   */
  async evaluateFindingConfigs(finding: NormalizedFinding, controlId: string): Promise<FindingConfigEvaluation> {
    const findingConfigs = (await this.findingConfigsCache.get(FINDING_CONFIGS_CACHE_KEY)) ?? [];

    let hasNotificationsEnabled = false;
    let hasDeadlineConfigured = false;
    const enforcementConfigIds: ConfigId[] = [];
    const enforcementDeadlineDays: number[] = [];

    for (const config of findingConfigs) {
      if (!passesControlFilter(config.controlIds ?? [], controlId)) continue;
      if (!passesSeverityFilter(config.severityFilter, finding.severity)) continue;
      if (!(await this.passesResourceFilters(finding, config.resourceFilterIds ?? []))) continue;

      // Metric flags additionally require the config's account scope to match,
      // mirroring the notification dispatcher's delivery-time gate.
      // `findByType('finding')` returns only enabled finding-type configs, so no
      // further enabled/type check is needed here.
      if (passesAccountScopeFilter(config.accountIds, finding.accountId)) {
        hasNotificationsEnabled = true;
        if (config.contentOptions.includeRemediationDeadline === true) {
          hasDeadlineConfigured = true;
        }
      }

      // Enforcement eligibility preserves prior behavior: it does not apply the
      // config-level account scope, and only counts configs with enforcement
      // fully switched on and a deadline day count set.
      if (isEnforcementEnabledConfig(config) && config.contentOptions.remediationDeadlineDays !== undefined) {
        enforcementConfigIds.push(config.configId);
        enforcementDeadlineDays.push(config.contentOptions.remediationDeadlineDays);
      }
    }

    return {
      hasNotificationsEnabled,
      hasDeadlineConfigured,
      enforcement: this.buildEnforcementResult(finding, controlId, enforcementConfigIds, enforcementDeadlineDays),
    };
  }

  /** Clears the cached finding configurations, forcing a fresh load on the next evaluation. */
  clearCache(): void {
    this.findingConfigsCache.clear();
  }

  private buildEnforcementResult(
    finding: NormalizedFinding,
    controlId: string,
    matchingConfigIds: ConfigId[],
    matchingDeadlineDays: number[],
  ): EligibilityResult {
    if (matchingConfigIds.length === 0) {
      return { isEligible: false, matchingConfigIds: [] };
    }

    const shortestDeadlineDays = Math.min(...matchingDeadlineDays);
    const remediationDueBy = computeRemediationDueBy(finding.createdAt, shortestDeadlineDays, this.clock.now());

    this.logger.debug('Finding is eligible for deadline enforcement', {
      findingId: finding.id,
      controlId,
      matchingConfigIds,
      shortestDeadlineDays,
      remediationDueBy,
    });

    return { isEligible: true, remediationDueBy, matchingConfigIds };
  }

  /**
   * Loads enabled, finding-type notification configurations. `findByType('finding')`
   * returns only enabled finding configs; enforcement and metric-flag predicates are
   * applied per-config during evaluation.
   */
  private async loadFindingConfigs(): Promise<NotificationConfigurationItem[]> {
    return this.notificationConfigurationRepository.findByType('finding');
  }

  private async passesResourceFilters(finding: NormalizedFinding, resourceFilterIds: string[]): Promise<boolean> {
    const result = await this.resourceFilterEvaluator.evaluateFilters(finding, resourceFilterIds, 'include');
    return result.passed;
  }
}
