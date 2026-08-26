// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { SNSClient, PublishBatchCommand, PublishBatchRequestEntry } from '@aws-sdk/client-sns';
import { Logger } from '@aws-lambda-powertools/logger';
import {
  NotificationEvent,
  NotificationConfigurationItem,
  NotificationType,
  NOTIFICATION_CACHE_TTL_MS,
  ResourceFilterDynamoDBItem,
  RemediationStatusFilter,
  normalizeRemediationStatus,
} from '@asr/data-models';
import { NotificationConfigurationRepository } from '../common/repositories/notificationConfigurationRepository';
import { NotificationBatchRepository } from '../common/repositories/notificationBatchRepository';
import { FiltersRepository } from '../common/repositories/filtersRepository';
import { LambdaCache } from '../common/utils/lambdaCache';
import { Clock, getClock } from '../common/utils/clock';
import { sendMetrics } from '../common/utils/metricsUtils';
import { arnMatchesPattern } from '../common/utils/wildcardMatch';
import {
  passesControlFilter,
  passesSeverityFilter,
  passesAccountScopeFilter,
} from '../common/utils/notificationFilters';

const DISPATCHER_PRINCIPAL = 'NotificationDispatcher';
const MS_PER_SECOND = 1_000;
const TTL_BUFFER_SECONDS = 60;
const DEFAULT_BATCH_DURATION = 5;
const DEFAULT_BATCH_UNIT = 'Minutes';

const BATCH_WINDOW_MS: Record<string, number> = {
  Minutes: 60_000,
  Hours: 3_600_000,
  Days: 86_400_000,
};

/** A notification configuration paired with its pre-resolved resource filters. */
interface ConfigWithResolvedFilters {
  readonly config: NotificationConfigurationItem;
  readonly resolvedFilters: ResourceFilterDynamoDBItem[];
}

export interface NotificationDispatcherDependencies {
  readonly configTableName: string;
  readonly batchesTableName: string;
  readonly resourceFiltersTableName: string;
  readonly dynamoDBClient: DynamoDBDocumentClient;
  readonly logger: Logger;
  readonly snsClient: SNSClient;
  readonly channelFanoutTopicArn: string;
  readonly clock?: Clock;
  readonly staleProcessingMs?: number;
}

export class NotificationDispatcherService {
  private readonly configRepo: NotificationConfigurationRepository;
  private readonly batchRepo: NotificationBatchRepository;
  private readonly filtersRepo: FiltersRepository;
  private readonly snsClient: SNSClient;
  private readonly channelFanoutTopicArn: string;
  private readonly logger: Logger;
  private readonly clock: Clock;
  private readonly configCache: LambdaCache<ConfigWithResolvedFilters[], NotificationType>;

  constructor(dependencies: NotificationDispatcherDependencies) {
    const {
      configTableName,
      batchesTableName,
      resourceFiltersTableName,
      dynamoDBClient,
      logger,
      snsClient,
      channelFanoutTopicArn,
      clock = getClock(),
      staleProcessingMs,
    } = dependencies;

    this.configRepo = new NotificationConfigurationRepository(configTableName, dynamoDBClient);
    this.batchRepo = new NotificationBatchRepository(DISPATCHER_PRINCIPAL, batchesTableName, dynamoDBClient, {
      staleProcessingMs,
    });
    this.filtersRepo = new FiltersRepository(resourceFiltersTableName, dynamoDBClient);
    this.snsClient = snsClient;
    this.channelFanoutTopicArn = channelFanoutTopicArn;
    this.logger = logger;
    this.clock = clock;
    this.configCache = new LambdaCache<ConfigWithResolvedFilters[], NotificationType>({
      ttlMs: NOTIFICATION_CACHE_TTL_MS,
      fetchFn: (key) => this.loadConfigsWithFilters(key),
      clock,
    });
  }

  clearCache(): void {
    this.configCache.clear();
  }

  async dispatch(event: NotificationEvent): Promise<void> {
    const configEntries = (await this.configCache.get(event.eventType)) ?? [];
    const matchingEntries = configEntries.filter((entry) => this.matchesAllCriteria(entry, event));

    // Logged at info so the dispatch decision (how many configs matched a given
    // finding event) is observable in the deployed stack, which runs at INFO.
    // This is a low-volume, per-event audit signal used to confirm severity /
    // control-id filtering behaved as configured.
    this.logger.info('Matched configurations', {
      eventId: event.eventId,
      matchCount: matchingEntries.length,
    });

    const results = await Promise.allSettled(matchingEntries.map((entry) => this.routeToDelivery(entry.config, event)));
    const isRejected = (r: PromiseSettledResult<void>): r is PromiseRejectedResult => r.status === 'rejected';
    const failures = results.filter(isRejected);
    if (failures.length > 0) {
      this.logger.error('Some notification configs failed delivery', {
        eventId: event.eventId,
        failedCount: failures.length,
        totalCount: matchingEntries.length,
        errors: failures.map((f) => f.reason?.message ?? String(f.reason)),
      });
      throw failures[0].reason;
    }
  }

  // ─── Config Loading ────────────────────────────────────────────────────────

  /**
   * Loads all enabled configs for the given event type and pre-resolves their
   * resource filter definitions in a single batched DynamoDB call. The result
   * is cached for NOTIFICATION_CACHE_TTL_MS to avoid repeated reads during
   * high-throughput SQS processing.
   *
   * A configured filter that no longer exists in DynamoDB is silently omitted by
   * BatchGetItem; the dispatcher tolerates this and matches the surviving filters.
   */
  private async loadConfigsWithFilters(eventType: NotificationType): Promise<ConfigWithResolvedFilters[]> {
    const configs = await this.configRepo.findByType(eventType);
    if (configs.length === 0) return [];

    const allFilterIds = [...new Set(configs.flatMap((c) => c.resourceFilterIds ?? []).filter(Boolean))];
    if (allFilterIds.length === 0) {
      return configs.map((config) => ({ config, resolvedFilters: [] }));
    }

    const filters = await this.filtersRepo.batchFindByIds(allFilterIds);
    const filterById = new Map(filters.map((f) => [f.filterId, f]));

    return configs.map((config) => {
      const requestedIds = config.resourceFilterIds ?? [];
      const resolvedFilters = requestedIds
        .map((id) => filterById.get(id))
        .filter((f): f is ResourceFilterDynamoDBItem => !!f);
      return { config, resolvedFilters };
    });
  }

  // ─── Event Matching ────────────────────────────────────────────────────────

  private matchesAllCriteria(entry: ConfigWithResolvedFilters, event: NotificationEvent): boolean {
    if (!passesAccountScopeFilter(entry.config.accountIds, event.accountId)) {
      return false;
    }
    if (!passesSeverityFilter(entry.config.severityFilter, event.severity)) {
      return false;
    }
    if (
      event.eventType === 'remediation' &&
      !this.passesRemediationStatusFilter(entry.config.remediationStatusFilter, event.remediationStatus)
    ) {
      return false;
    }
    if (!passesControlFilter(entry.config.controlIds ?? [], event.controlId)) return false;
    if (!this.passesResourceFilterCriteria(entry, event)) return false;
    return true;
  }

  private passesRemediationStatusFilter(
    filter: RemediationStatusFilter | undefined,
    eventStatus: string | undefined,
  ): boolean {
    if (!filter || filter.length === 0 || filter.includes('All')) return true;
    const normalized = normalizeRemediationStatus(eventStatus);
    return filter.includes(normalized);
  }

  /**
   * Evaluates resource filters with "include-any" semantics: when at least one
   * filter id is attached to the config, the event passes only if it matches
   * at least one resolved filter. Filter ids that no longer exist in DynamoDB
   * (e.g. the filter was deleted after the config was written) are skipped —
   * the event still passes if any surviving filter matches. Transient DynamoDB
   * failures are surfaced upstream before this check runs (loadConfigsWithFilters
   * throws rather than caching a partial view), so reaching this method means
   * the filter set is authoritative.
   */
  private passesResourceFilterCriteria(entry: ConfigWithResolvedFilters, event: NotificationEvent): boolean {
    const requestedFilterIds = entry.config.resourceFilterIds ?? [];
    if (requestedFilterIds.length === 0) return true;
    return entry.resolvedFilters.some((filter) => this.resourceFilterMatchesEvent(filter, event));
  }

  private resourceFilterMatchesEvent(filter: ResourceFilterDynamoDBItem, event: NotificationEvent): boolean {
    const accountIds = this.normalizeToArray(filter.accountIds);
    const arnPatterns = this.normalizeToArray(filter.arnPatterns);

    // Filter with only tag/OU criteria can't be evaluated at dispatch time
    if (accountIds.length === 0 && arnPatterns.length === 0) {
      const hasTags = (filter.tags ?? []).length > 0;
      const hasOrganizationalUnits = this.normalizeToArray(filter.organizationalUnits).length > 0;
      return !(hasTags || hasOrganizationalUnits); // empty filter = match all; tag/OU only = no match
    }

    if (accountIds.length > 0 && !accountIds.includes(event.accountId)) return false;
    if (arnPatterns.length > 0 && !arnPatterns.some((pattern) => arnMatchesPattern(event.resourceId, pattern))) {
      return false;
    }
    return true;
  }

  private normalizeToArray(value: Set<string> | string[] | undefined): string[] {
    if (!value) return [];
    return value instanceof Set ? [...value] : value;
  }

  // ─── Delivery Routing ──────────────────────────────────────────────────────
  // Delivery is at-least-once: if one config fails, the SQS message is retried
  // and previously-succeeded configs will be re-delivered. Downstream consumers
  // deduplicate on configId + eventId.

  private async routeToDelivery(config: NotificationConfigurationItem, event: NotificationEvent): Promise<void> {
    if (config.batchWindow.enabled) {
      await this.addEventToBatch(config, event);
    } else {
      await this.publishImmediately(config, event);
    }
  }

  private async addEventToBatch(config: NotificationConfigurationItem, event: NotificationEvent): Promise<void> {
    const duration = config.batchWindow.duration ?? DEFAULT_BATCH_DURATION;
    const unit = config.batchWindow.unit ?? DEFAULT_BATCH_UNIT;
    const windowMs = duration * (BATCH_WINDOW_MS[unit] ?? BATCH_WINDOW_MS.Minutes);
    const windowEnd = new Date(Math.ceil(this.clock.now().getTime() / windowMs) * windowMs).toISOString();
    const expireAt = Math.floor(new Date(windowEnd).getTime() / MS_PER_SECOND) + TTL_BUFFER_SECONDS;

    // Dedup: claim this event for this config. If the Lambda crashes between claim and
    // append, the event is lost until the dedup TTL expires — acceptable for at-least-once.
    const isNew = await this.batchRepo.tryClaimEvent(config.configId, event.eventId, expireAt);
    if (!isNew) {
      this.logger.debug('Duplicate event skipped', { configId: config.configId, eventId: event.eventId });
      return;
    }

    const field = event.eventType === 'finding' ? 'findingIds' : 'remediationIds';
    try {
      await this.batchRepo.appendEventId(config.configId, windowEnd, event.eventId, field, expireAt);
    } catch (error) {
      // Rollback the dedup claim so SQS retry can re-process this event.
      try {
        await this.batchRepo.deleteEventClaim(config.configId, event.eventId);
      } catch (rollbackError) {
        this.logger.error('Failed to rollback dedup claim; event may be lost until TTL expires', {
          configId: config.configId,
          eventId: event.eventId,
          rollbackError,
        });
      }
      throw error;
    }
  }

  private async publishImmediately(config: NotificationConfigurationItem, event: NotificationEvent): Promise<void> {
    const enabledChannels = config.deliveryChannels.filter((ch) => ch.enabled);
    if (enabledChannels.length === 0) return;

    const entries: PublishBatchRequestEntry[] = enabledChannels.map((channel, index) => ({
      Id: `${index}`,
      Message: JSON.stringify({
        configId: config.configId,
        configName: config.name,
        contentOptions: config.contentOptions,
        channel,
        event,
      }),
      MessageAttributes: {
        channelType: { DataType: 'String', StringValue: channel.type },
        configId: { DataType: 'String', StringValue: config.configId },
      },
    }));

    const dispatchStartMs = this.clock.now().getTime();
    const response = await this.snsClient.send(
      new PublishBatchCommand({ TopicArn: this.channelFanoutTopicArn, PublishBatchRequestEntries: entries }),
    );

    const dispatchLatencyMs = this.clock.now().getTime() - dispatchStartMs;
    await this.emitDispatchLatencyMetric(config.configId, enabledChannels.length, dispatchLatencyMs);

    const failedEntries = response.Failed ?? [];
    if (failedEntries.length > 0) {
      this.logger.error('PublishBatch partial failure', {
        configId: config.configId,
        eventId: event.eventId,
        failedCount: failedEntries.length,
        totalCount: enabledChannels.length,
        failedEntries,
      });
      throw new Error(
        `PublishBatch partial failure: ${failedEntries.length}/${enabledChannels.length} entries failed for config ${config.configId}`,
      );
    }
  }

  /**
   * Publishes a single `notification_dispatch_latency` data point to the
   * SolutionsMetrics API for the one PublishBatch call that hands all enabled
   * channels off to the fanout topic, tagged with config_id and the channel
   * count. The latency is batch-level (not per-channel), so it is emitted once
   * rather than duplicated per channel. Best-effort — sendMetrics never rejects,
   * so this cannot disrupt dispatch.
   */
  private async emitDispatchLatencyMetric(configId: string, channelCount: number, latencyMs: number): Promise<void> {
    await sendMetrics({
      notification_dispatch_latency: latencyMs,
      config_id: configId,
      channel_count: channelCount,
    });
  }
}
