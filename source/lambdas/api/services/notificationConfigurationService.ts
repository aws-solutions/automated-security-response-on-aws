// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { ConditionalCheckFailedException } from '@aws-sdk/client-dynamodb';
import { SNSClient } from '@aws-sdk/client-sns';
import { OrganizationsClient } from '@aws-sdk/client-organizations';
import { AccountClient } from '@aws-sdk/client-account';
import {
  ConfigId,
  CreateNotificationConfigurationRequest,
  UpdateNotificationConfigurationRequest,
  ToggleStatusRequest,
  NotificationConfigurationItem,
  DeliveryChannelConfig,
  EmailSubscriptionStatusWithType,
  ReconciliationTaskType,
} from '@asr/data-models';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { ControlsRepository } from '../../common/repositories/controlsRepository';
import { FiltersRepository } from '../../common/repositories/filtersRepository';
import { UserAccountMappingRepository } from '../../common/repositories/userAccountMappingRepository';
import { EmailTopicLifecycleService } from '../../notification-channels/email-topic-lifecycle';
import { EmailRecipientResolver, ResolvableRecipientType } from '../../common/services/emailRecipientResolver';
import { Clock, getClock } from '../../common/utils/clock';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { IdGenerator, getIdGenerator } from '../../common/utils/idGenerator';
import { NotificationBatchRepository } from '../../common/repositories/notificationBatchRepository';
import { isEnforcementEnabledConfig } from '../../common/utils/remediationDeadline';
import {
  BadRequestError,
  ConflictError,
  CONFLICT_ERROR_MESSAGE,
  ForbiddenError,
  HttpError,
  ServiceUnavailableError,
  VersionConflictError,
} from '../../common/utils/httpErrors';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { apiLambdaEnvironment, apiLambdaRuntimeEnvironment } from '../apiLambdaEnvironment';
import { computeChannelChange } from '../adminActivity/channelDiff';
import { AdminActivityNotifier, AdminActorContext, ChannelActivityAction } from './adminActivityNotifier';

type ConfigurationCrudOperation = 'Create' | 'Update' | 'Delete';

export class NotificationConfigurationService {
  private dynamoDBClient: DynamoDBDocumentClient | undefined;
  private repository: NotificationConfigurationRepository | undefined;
  private controlsRepository: ControlsRepository | undefined;
  private filtersRepository: FiltersRepository | undefined;
  private userAccountMappingRepository: UserAccountMappingRepository | undefined;
  private emailLifecycle: EmailTopicLifecycleService | undefined;
  private snsClient: SNSClient | undefined;
  private recipientResolver: EmailRecipientResolver | undefined;
  private notificationBatchRepository: NotificationBatchRepository | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly clock: Clock = getClock(),
    private readonly idGenerator: IdGenerator = getIdGenerator(),
    private readonly adminActivityNotifier: AdminActivityNotifier = new AdminActivityNotifier(logger),
  ) {}

  /** Emits the `configuration_crud` metric for a mutating configuration operation. */
  private async emitConfigurationCrudMetric(operation: ConfigurationCrudOperation): Promise<void> {
    await sendMetrics({ configuration_crud: 1, operation });
  }

  /**
   * Records a notification-channel mutation: emits the `configuration_crud` metric and the
   * admin-activity notification for the channel. The notifier is fail-open, so a delivery failure
   * never fails the admin operation that triggered it.
   */
  private async emitChannelChange(
    actor: AdminActorContext,
    crudOperation: ConfigurationCrudOperation,
    action: ChannelActivityAction,
    config: NotificationConfigurationItem,
    changedFields?: string[],
  ): Promise<void> {
    await this.emitConfigurationCrudMetric(crudOperation);
    await this.adminActivityNotifier.notify({
      action,
      actorEmail: actor.actorEmail,
      actorGroups: actor.actorGroups,
      resourceType: 'notification-channel',
      resourceId: config.configId,
      resourceName: config.name,
      changedFields,
    });
  }

  private getDynamoDBClient(): DynamoDBDocumentClient {
    this.dynamoDBClient ??= createDynamoDBClient({ maxAttempts: 10 });
    return this.dynamoDBClient;
  }

  private getRepository(): NotificationConfigurationRepository {
    this.repository ??= new NotificationConfigurationRepository(
      apiLambdaEnvironment().NOTIFICATION_CONFIG_TABLE_NAME,
      this.getDynamoDBClient(),
    );
    return this.repository;
  }

  private getControlsRepository(): ControlsRepository {
    this.controlsRepository ??= new ControlsRepository(
      apiLambdaEnvironment().REMEDIATION_CONFIG_TABLE_NAME,
      this.getDynamoDBClient(),
    );
    return this.controlsRepository;
  }

  private getFiltersRepository(): FiltersRepository {
    this.filtersRepository ??= new FiltersRepository(
      apiLambdaEnvironment().RESOURCE_FILTERS_TABLE_NAME,
      this.getDynamoDBClient(),
    );
    return this.filtersRepository;
  }

  private getSnsClient(): SNSClient {
    this.snsClient ??= new SNSClient({});
    return this.snsClient;
  }

  private getEmailLifecycle(): EmailTopicLifecycleService {
    this.emailLifecycle ??= new EmailTopicLifecycleService(
      this.getSnsClient(),
      this.logger,
      apiLambdaEnvironment().AWS_ACCOUNT_ID,
      apiLambdaRuntimeEnvironment().AWS_REGION,
      apiLambdaEnvironment().AWS_PARTITION,
    );
    return this.emailLifecycle;
  }

  private getRecipientResolver(): EmailRecipientResolver {
    this.recipientResolver ??= new EmailRecipientResolver({
      organizationsClient: new OrganizationsClient({}),
      accountClient: new AccountClient({}),
      fetchAccountOperatorEmails: () => this.getUserAccountMappingRepository().findAllUserIds(),
      accountId: apiLambdaEnvironment().AWS_ACCOUNT_ID,
      logger: this.logger,
    });
    return this.recipientResolver;
  }

  private getUserAccountMappingRepository(): UserAccountMappingRepository {
    this.userAccountMappingRepository ??= new UserAccountMappingRepository(
      'NotificationConfigurationService',
      apiLambdaEnvironment().USER_ACCOUNT_MAPPING_TABLE_NAME,
      this.getDynamoDBClient(),
    );
    return this.userAccountMappingRepository;
  }

  async listSubscriptionStatuses(
    configId: ConfigId,
  ): Promise<{ statuses: EmailSubscriptionStatusWithType[]; hasFailure: boolean }> {
    const config = await this.getConfigurationById(configId);
    const recipientTypes = this.extractRecipientTypes(config);

    // Resolve all types in parallel (fixes N+1 serial awaits). Use first-write-wins
    // so when two types resolve to the same email, the earlier type in the list wins.
    const emailToType = new Map<string, ResolvableRecipientType>();

    const perType = await Promise.all(
      recipientTypes.map(async (type) => {
        const result = await this.getRecipientResolver().resolveAll([type]);
        return { type, ...result };
      }),
    );

    const hasFailure = perType.some((r) => r.hasFailure);

    for (const { type, emails } of perType) {
      for (const email of emails) {
        if (!emailToType.has(email)) emailToType.set(email, type);
      }
    }

    const statuses = await this.getEmailLifecycle().listSubscriptionStatuses(configId);
    return {
      statuses: statuses.map((s) => ({ ...s, recipientType: emailToType.get(s.email) })),
      hasFailure,
    };
  }

  async resendConfirmation(configId: ConfigId, email: string): Promise<void> {
    return this.getEmailLifecycle().resendConfirmation(configId, email);
  }

  async getAllConfigurations(): Promise<{ configurations: NotificationConfigurationItem[] }> {
    const configurations = await this.getRepository().findAll();
    this.logger.info('Successfully retrieved notification configurations', { count: configurations.length });
    return { configurations };
  }

  async getConfigurationById(configId: ConfigId): Promise<NotificationConfigurationItem> {
    return await this.getRepository().getConfigById(configId);
  }

  async createConfiguration(
    request: CreateNotificationConfigurationRequest,
    actor: AdminActorContext,
  ): Promise<NotificationConfigurationItem> {
    const createdBy = actor.actorEmail;
    await this.validateForeignIds(request.controlIds ?? [], request.resourceFilterIds ?? []);

    const configId = this.idGenerator.randomUUID() as ConfigId;
    const createdAt = this.clock.now().toISOString();

    // Atomically reserve the name — prevents race conditions
    try {
      await this.getRepository().reserveName(request.name, configId);
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new BadRequestError(`A notification configuration with the name "${request.name}" already exists`);
      }
      throw error;
    }

    const item: NotificationConfigurationItem = {
      configId,
      ...request,
      version: 1,
      createdAt,
      createdBy,
    };

    this.logger.info('Creating notification configuration', { configId, createdBy });

    try {
      await this.getRepository().create(item, createdBy);
    } catch (error) {
      // Roll back the name reservation on failure
      try {
        await this.getRepository().releaseName(request.name);
      } catch (releaseError) {
        this.logger.error('Failed to release name lock during rollback', {
          name: request.name,
          configId,
          releaseError,
        });
      }
      if (error instanceof ConditionalCheckFailedException) {
        throw new ConflictError('A configuration with this ID already exists');
      }
      throw error;
    }

    this.logger.info('Successfully created notification configuration', { configId });

    await this.enqueueReconciliationTasks(null, item);

    await this.syncEmailTopicForConfig(item);

    await this.emitChannelChange(actor, 'Create', 'CHANNEL_CREATED', item);

    return item;
  }

  async deleteConfiguration(
    configId: ConfigId,
    actor: AdminActorContext,
  ): Promise<NotificationConfigurationItem | null> {
    const existing = await this.getRepository().findConfigById(configId);
    if (!existing) {
      this.logger.info('Configuration not found, nothing to delete', { configId });
      return null;
    }

    this.logger.info('Deleting notification configuration', { configId });

    try {
      await this.getRepository().deleteWithNameRelease(configId, existing.name);
    } catch (error) {
      if ((error as Error).name === 'TransactionCanceledException') {
        throw new ConflictError('Configuration was modified by another request during deletion. Please retry.');
      }
      throw error;
    }

    await this.enqueueReconciliationTasks(existing, null);

    await this.deleteEmailTopicForConfig(configId);

    this.logger.info('Successfully deleted notification configuration', { configId });

    await this.emitChannelChange(actor, 'Delete', 'CHANNEL_DELETED', existing);

    return existing;
  }

  private async validateForeignIds(controlIds: string[], resourceFilterIds: string[]): Promise<void> {
    const errors: string[] = [];

    if (controlIds.length > 0) {
      const { foundControlIds, isComplete } = await this.getControlsRepository().batchFindByIds(controlIds);
      if (!isComplete) {
        throw new ServiceUnavailableError(
          'Could not verify all controlIds against the remediation config table; please retry',
        );
      }
      const foundSet = new Set(foundControlIds);
      const unknownControlIds = Array.from(new Set(controlIds.filter((id) => !foundSet.has(id))));
      if (unknownControlIds.length > 0) {
        errors.push(`Unknown controlIds: ${unknownControlIds.join(', ')}`);
      }
    }

    if (resourceFilterIds.length > 0) {
      // A missing resourceFilterId is a client error: FiltersRepository.batchFindByIds returns the
      // surviving filters (BatchGetItem omits absent keys), so derive the unknown IDs from the
      // returned filters directly, mirroring the controlIds branch above.
      const filters = await this.getFiltersRepository().batchFindByIds(resourceFilterIds);
      const foundSet = new Set(filters.map((f) => f.filterId));
      const unknownFilterIds = Array.from(new Set(resourceFilterIds.filter((id) => !foundSet.has(id))));
      if (unknownFilterIds.length > 0) {
        errors.push(`Unknown resourceFilterIds: ${unknownFilterIds.join(', ')}`);
      }
    }

    if (errors.length > 0) {
      throw new BadRequestError(errors.join('; '));
    }
  }

  private async updateWithVersionConflictHandling(
    item: NotificationConfigurationItem,
    expectedVersion: number,
    updatedBy: string,
  ): Promise<void> {
    try {
      await this.getRepository().updateWithVersion(item, expectedVersion, updatedBy);
    } catch (error) {
      if (error instanceof VersionConflictError) {
        throw new ConflictError(CONFLICT_ERROR_MESSAGE, {
          code: 'VERSION_CONFLICT',
          context: { configId: item.configId, expectedVersion, currentVersion: error.currentVersion },
        });
      }
      throw error;
    }
  }

  async updateConfiguration(
    configId: ConfigId,
    request: UpdateNotificationConfigurationRequest,
    actor: AdminActorContext,
    existingConfig?: NotificationConfigurationItem,
  ): Promise<NotificationConfigurationItem> {
    const updatedBy = actor.actorEmail;
    await this.validateForeignIds(request.controlIds ?? [], request.resourceFilterIds ?? []);

    // Reuse the caller's pre-fetched config (e.g. the operator authorization read) when supplied,
    // avoiding a second DynamoDB read and closing the time-of-check/time-of-use window between the
    // authorization fetch and this update. The optimistic-locking version check below still guards
    // against any concurrent mutation. Admin paths pass nothing and fall back to a fresh read.
    const existing = existingConfig ?? (await this.getConfigurationById(configId));

    this.logger.info('Updating notification configuration', { configId, updatedBy });

    const { version, ...fields } = request;
    const merged: NotificationConfigurationItem = {
      ...existing,
      ...fields,
      severityFilter: fields.severityFilter,
      remediationStatusFilter: fields.remediationStatusFilter,
      controlIds: fields.controlIds,
      resourceFilterIds: fields.resourceFilterIds,
      accountIds: fields.accountIds,
    };

    if (request.name === existing.name) {
      await this.updateWithVersionConflictHandling(merged, version, updatedBy);
    } else {
      await this.updateWithNameChange(merged, existing.name, request.name, version, updatedBy);
    }

    const updated = await this.getRepository().findConfigById(configId);
    if (!updated) {
      throw new HttpError(500, `Configuration ${configId} not found after update`);
    }

    await this.enqueueReconciliationTasks(existing, updated);

    await this.syncEmailTopicForConfig(updated);

    this.logger.info('Successfully updated notification configuration', { configId });

    const { action, changedFields } = computeChannelChange(existing, updated);
    await this.emitChannelChange(actor, 'Update', action, updated, changedFields);

    return updated;
  }

  private async updateWithNameChange(
    merged: NotificationConfigurationItem,
    oldName: string,
    newName: string,
    version: number,
    updatedBy: string,
  ): Promise<void> {
    try {
      await this.getRepository().reserveName(newName, merged.configId);
    } catch (error) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new BadRequestError(`A notification configuration with the name "${newName}" already exists`);
      }
      throw error;
    }

    try {
      await this.updateWithVersionConflictHandling(merged, version, updatedBy);
    } catch (error) {
      try {
        await this.getRepository().releaseName(newName);
      } catch (releaseError) {
        this.logger.error('Failed to release new name lock during rollback', { name: newName, releaseError });
      }
      throw error;
    }

    try {
      await this.getRepository().releaseName(oldName);
    } catch (releaseError) {
      this.logger.error('Failed to release old name lock after rename', { name: oldName, releaseError });
    }
  }

  async toggleStatus(
    configId: ConfigId,
    request: ToggleStatusRequest,
    actor: AdminActorContext,
  ): Promise<NotificationConfigurationItem> {
    const updatedBy = actor.actorEmail;
    const existing = await this.getConfigurationById(configId);

    this.logger.info('Toggling notification configuration status', { configId, enabled: request.enabled });

    await this.updateWithVersionConflictHandling({ ...existing, enabled: request.enabled }, request.version, updatedBy);

    const updated = await this.getRepository().findConfigById(configId);
    if (!updated) {
      throw new HttpError(500, `Configuration ${configId} not found after toggle`);
    }

    await this.enqueueReconciliationTasks(existing, updated);

    this.logger.info('Successfully toggled notification configuration status', { configId, enabled: request.enabled });

    await this.emitChannelChange(actor, 'Update', 'CHANNEL_TOGGLED', updated, ['enabled']);

    return updated;
  }

  /**
   * Lazily constructs the NotificationBatches repository used to enqueue reconciliation tasks,
   * memoizing it per service instance (consistent with the other `get*Repository()` accessors).
   * Returns `undefined` when the table name is absent — deployments where the API Lambda is not
   * granted access to the table — so callers treat that as "reconciliation unavailable" and skip
   * gracefully.
   */
  private getNotificationBatchRepository(): NotificationBatchRepository | undefined {
    const tableName = apiLambdaEnvironment().NOTIFICATION_BATCHES_TABLE_NAME;
    if (!tableName) return undefined;
    this.notificationBatchRepository ??= new NotificationBatchRepository(
      'NotificationConfigurationService',
      tableName,
      this.getDynamoDBClient(),
      { clock: this.clock, idGenerator: this.idGenerator },
    );
    return this.notificationBatchRepository;
  }

  /** Order-insensitive equality for the string-array filters that drive enforcement matching. */
  private stringArrayContentsMatch(first: string[] = [], second: string[] = []): boolean {
    if (first.length !== second.length) return false;
    const firstSet = new Set(first);
    return second.every((value) => firstSet.has(value));
  }

  /**
   * Classifies a configuration change into the reconciliation work it requires. Returns an empty
   * array when no enforcement-relevant change occurred. `oldConfig` is `null` for creates and
   * `newConfig` is `null` for deletes (`null` signals an intentionally absent snapshot).
   *
   * A single update can change both the deadline length and the targeted findings (control IDs or
   * resource filters) at once, and those are handled by distinct reconciliation paths: the
   * `deadlineChange` task only recomputes findings that already reference the config, while the
   * `filterChange` task stamps newly-targeted findings and clears no-longer-targeted ones. Each
   * applicable type is therefore returned so both kinds of work are enqueued; reconciliation reads
   * live config state and is idempotent, so running both converges regardless of processing order.
   */
  private determineReconciliationTaskTypes(
    oldConfig: NotificationConfigurationItem | null,
    newConfig: NotificationConfigurationItem | null,
  ): ReconciliationTaskType[] {
    const wasEnforcing = oldConfig ? isEnforcementEnabledConfig(oldConfig) : false;
    const isEnforcing = newConfig ? isEnforcementEnabledConfig(newConfig) : false;

    if (!wasEnforcing && isEnforcing) return ['enable'];
    if (wasEnforcing && !isEnforcing) return ['disable'];
    if (!wasEnforcing && !isEnforcing) return [];

    // Reaching here means both configs enforce deadlines, which guarantees both snapshots are
    // present; the guard narrows the type so the comparisons below need no non-null assertions.
    if (!oldConfig || !newConfig) return [];

    // Both the previous and current config enforce deadlines: collect every input that changed.
    const taskTypes: ReconciliationTaskType[] = [];
    if (oldConfig.contentOptions.remediationDeadlineDays !== newConfig.contentOptions.remediationDeadlineDays) {
      taskTypes.push('deadlineChange');
    }
    if (
      !this.stringArrayContentsMatch(oldConfig.controlIds ?? [], newConfig.controlIds ?? []) ||
      !this.stringArrayContentsMatch(oldConfig.resourceFilterIds ?? [], newConfig.resourceFilterIds ?? [])
    ) {
      taskTypes.push('filterChange');
    }
    return taskTypes;
  }

  /**
   * Writes a reconciliation task for each enforcement-relevant change a configuration underwent.
   * This is best-effort: the configuration write has already succeeded, so a missing table name or
   * a write failure is logged and swallowed rather than failing the API request. Each task type is
   * enqueued independently so one write failing does not prevent the others.
   */
  private async enqueueReconciliationTasks(
    oldConfig: NotificationConfigurationItem | null,
    newConfig: NotificationConfigurationItem | null,
  ): Promise<void> {
    const taskTypes = this.determineReconciliationTaskTypes(oldConfig, newConfig);
    if (taskTypes.length === 0) return;

    const configId = (newConfig ?? oldConfig)?.configId;
    const repository = this.getNotificationBatchRepository();
    if (!repository) {
      this.logger.warn('NotificationBatches table name unavailable; skipping reconciliation task creation', {
        configId,
        taskTypes,
      });
      return;
    }

    for (const taskType of taskTypes) {
      try {
        const task = await repository.createReconciliationTask(
          taskType,
          oldConfig ?? undefined,
          newConfig ?? undefined,
        );
        this.logger.info('Created reconciliation task for configuration change', {
          configId,
          taskType,
          reconciliationTaskId: task.configId,
        });
      } catch (error) {
        this.logger.warn('Failed to create reconciliation task for configuration change', {
          configId,
          taskType,
          error,
        });
      }
    }
  }

  private extractCustomEmails(item: NotificationConfigurationItem): string[] {
    const emailChannel = item.deliveryChannels.find(
      (ch): ch is Extract<DeliveryChannelConfig, { type: 'email' }> => ch.type === 'email' && ch.enabled,
    );
    return (
      emailChannel?.recipients.filter((r) => r.recipientType === 'custom').flatMap((r) => r.emailAddresses ?? []) ?? []
    );
  }

  private extractRecipientTypes(item: NotificationConfigurationItem): ResolvableRecipientType[] {
    const emailChannel = item.deliveryChannels.find(
      (ch): ch is Extract<DeliveryChannelConfig, { type: 'email' }> => ch.type === 'email' && ch.enabled,
    );
    return (
      emailChannel?.recipients
        .map((r) => r.recipientType)
        .filter((t): t is ResolvableRecipientType => t !== 'custom') ?? []
    );
  }

  private hasEnabledEmailChannel(item: NotificationConfigurationItem): boolean {
    return item.deliveryChannels.some((ch) => ch.type === 'email' && ch.enabled);
  }

  private async syncEmailTopicForConfig(item: NotificationConfigurationItem): Promise<void> {
    try {
      if (!this.hasEnabledEmailChannel(item)) {
        await this.getEmailLifecycle().deleteTopic(item.configId);
        return;
      }
      await this.getEmailLifecycle().createTopic(item.configId);
      const customEmails = this.extractCustomEmails(item);
      const recipientTypes = this.extractRecipientTypes(item);
      const { emails: resolvedEmails, hasFailure } = await this.getRecipientResolver().resolveAll(recipientTypes);
      const allEmails = [...new Set([...customEmails, ...resolvedEmails])];
      await this.getEmailLifecycle().syncSubscriptions(item.configId, allEmails, hasFailure);
    } catch (error) {
      // Best-effort: config is already persisted, topic sync is non-critical
      this.logger.warn('Failed to sync email topic for config', { configId: item.configId, error });
    }
  }

  private async deleteEmailTopicForConfig(configId: ConfigId): Promise<void> {
    try {
      await this.getEmailLifecycle().deleteTopic(configId);
    } catch (error) {
      // Best-effort: config is already deleted, topic cleanup is non-critical
      this.logger.warn('Failed to delete email topic for removed config', { configId, error });
    }
  }

  /**
   * Validates that an account operator may mutate an existing config. Edit authority is creator-based:
   * an operator may only modify the configurations they created. Configurations created by another
   * operator, or by an admin (including global configs), are read-only to the operator. Admins and
   * delegated admins bypass this check entirely and may modify any configuration.
   */
  static assertOperatorIsCreator(operatorEmail: string, config: { createdBy?: string }): void {
    if (config.createdBy !== operatorEmail) {
      throw new ForbiddenError('Account operators can only modify notification configurations they created');
    }
  }

  /**
   * Validates that an account operator's requested accountIds (if provided) are all owned.
   * If accountIds are not provided, the backend auto-assigns all owned accounts.
   */
  static assertOperatorOwnsRequestedAccounts(authorizedAccounts: string[], accountIds: string[] | undefined): void {
    if (!accountIds || accountIds.length === 0) return;
    const ownedAccounts = new Set(authorizedAccounts);
    const unauthorized = accountIds.filter((id) => !ownedAccounts.has(id));
    if (unauthorized.length > 0) {
      throw new ForbiddenError('You do not have access to one or more of the specified accounts');
    }
  }

  /**
   * Unsubscribes an email address from all notification config SNS topics.
   * Called when a user is deleted to ensure they stop receiving notifications.
   * Best-effort — failures are logged but not propagated.
   */
  async unsubscribeEmailFromAllConfigs(email: string): Promise<void> {
    try {
      const allConfigs = await this.getRepository().findAll();
      const configsWithEmail = allConfigs.filter((config) => this.hasEnabledEmailChannel(config));

      for (const config of configsWithEmail) {
        try {
          const statuses = await this.getEmailLifecycle().listSubscriptionStatuses(config.configId);
          const match = statuses.find(
            (s) => s.email === email && s.subscriptionArn && s.subscriptionArn !== 'PendingConfirmation',
          );
          if (match) {
            await this.getEmailLifecycle().unsubscribe(match.subscriptionArn);
            this.logger.info('Unsubscribed deleted user from notification config', {
              configId: config.configId,
              email,
            });
          }
        } catch (error) {
          this.logger.warn('Failed to unsubscribe email from config, continuing', {
            configId: config.configId,
            email,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    } catch (error) {
      this.logger.warn('Failed to unsubscribe email from notification configs', {
        email,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Reconciles an operator's notification configurations after their account assignment changes,
   * keeping each config's delivery scope in lockstep with the operator's current account access.
   *
   * A no-op when the update did not touch accounts (`newAccountIds` is `undefined`). Otherwise every
   * config the operator created is re-scoped to exactly `newAccountIds` via
   * {@link syncOperatorConfigsToOwnedAccounts}. Best-effort: the delegate logs and swallows its own
   * failures, so a reconciliation problem never fails the user update that triggered it.
   */
  async reconcileOperatorAccountChange(operatorEmail: string, newAccountIds: string[] | undefined): Promise<void> {
    if (newAccountIds === undefined) return;
    await this.syncOperatorConfigsToOwnedAccounts(operatorEmail, newAccountIds);
  }

  /**
   * Reconciles an operator's notification configurations after the operator is deleted. A deleted
   * operator owns no accounts, so every config they created is disabled and de-scoped via
   * {@link syncOperatorConfigsToOwnedAccounts} with an empty owned-account set. Best-effort.
   */
  async reconcileAfterOperatorDeletion(operatorEmail: string): Promise<void> {
    await this.syncOperatorConfigsToOwnedAccounts(operatorEmail, []);
  }

  /**
   * Re-scopes every notification config an operator created so its `accountIds` exactly match the
   * operator's current owned accounts. When the operator owns no accounts, each config is disabled
   * and de-scoped instead. This overwrite keeps a config's delivery scope in sync with the
   * operator's access; any narrower per-config scoping is normalized to the full owned set.
   *
   * Best-effort — failures are logged but not propagated. Each affected config is reconciled
   * independently so one failure does not abort the rest, and version conflicts (a concurrent
   * mutation between the {@link findAll} read and the conditional write) trigger a single
   * re-read-and-retry rather than being silently dropped.
   */
  async syncOperatorConfigsToOwnedAccounts(operatorEmail: string, ownedAccounts: string[]): Promise<void> {
    let allConfigs: NotificationConfigurationItem[];
    try {
      allConfigs = await this.getRepository().findAll();
    } catch (error) {
      this.logger.warn('Failed to load notification configs for operator account reconciliation', {
        operatorEmail,
        ownedAccounts,
        error: error instanceof Error ? error.message : String(error),
      });
      return;
    }

    const operatorConfigs = allConfigs.filter((config) => config.createdBy === operatorEmail);

    for (const config of operatorConfigs) {
      await this.reconcileConfigToOwnedAccounts(config, ownedAccounts, operatorEmail);
    }
  }

  /**
   * Syncs a single config to the operator's owned accounts, retrying once on a version conflict.
   *
   * The config snapshot originates from a prior {@link findAll}; a concurrent mutation between that
   * read and the conditional write surfaces as a {@link VersionConflictError}. Rather than silently
   * dropping the reconciliation — which would leave a config scoped to accounts the operator no
   * longer owns — we re-read the config and retry once against the fresh version. A conflict that
   * persists past the retry is logged at error level so it surfaces in operational dashboards.
   */
  private async reconcileConfigToOwnedAccounts(
    config: NotificationConfigurationItem,
    ownedAccounts: string[],
    operatorEmail: string,
  ): Promise<void> {
    try {
      await this.applyAccountSync(config, ownedAccounts, operatorEmail);
    } catch (error) {
      if (!(error instanceof VersionConflictError)) {
        this.logger.warn('Failed to reconcile notification config to operator owned accounts', {
          configId: config.configId,
          operatorEmail,
          ownedAccounts,
          error: error instanceof Error ? error.message : String(error),
        });
        return;
      }

      // A concurrent write won the race; re-read the latest version and retry once.
      try {
        const fresh = await this.getRepository().findConfigById(config.configId);
        if (!fresh) return; // Deleted concurrently — nothing left to reconcile.
        await this.applyAccountSync(fresh, ownedAccounts, operatorEmail);
      } catch (retryError) {
        this.logger.error('Version conflict persisted while reconciling notification config to owned accounts', {
          configId: config.configId,
          operatorEmail,
          ownedAccounts,
          error: retryError instanceof Error ? retryError.message : String(retryError),
        });
      }
    }
  }

  /**
   * Overwrites a config's `accountIds` with the operator's owned accounts, or disables and de-scopes
   * it when the operator owns none. Skips configs already in the desired state to avoid issuing a
   * spurious, version-bumping write. The config's enabled state is otherwise preserved; a config
   * that was auto-disabled by a prior reconciliation stays disabled even when accounts are restored.
   */
  private async applyAccountSync(
    config: NotificationConfigurationItem,
    ownedAccounts: string[],
    operatorEmail: string,
  ): Promise<void> {
    const currentAccounts = config.accountIds ?? [];

    if (ownedAccounts.length === 0) {
      if (config.enabled === false && currentAccounts.length === 0) return; // already reconciled
      await this.getRepository().updateWithVersion(
        { ...config, enabled: false, accountIds: undefined },
        config.version,
        'system',
      );
      this.logger.info('Disabled notification config — operator owns no accounts', {
        configId: config.configId,
        operatorEmail,
      });
      return;
    }

    if (this.stringArrayContentsMatch(currentAccounts, ownedAccounts)) return; // already in sync

    await this.getRepository().updateWithVersion({ ...config, accountIds: ownedAccounts }, config.version, 'system');
    this.logger.info('Synced notification config account scope to operator owned accounts', {
      configId: config.configId,
      operatorEmail,
      ownedAccounts,
    });
  }
}
