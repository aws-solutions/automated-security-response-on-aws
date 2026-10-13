// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, DeleteCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { AbstractRepository, DynamoDBItem } from './abstractRepository';
import { UserAccountMapping, userAccountIds } from '@asr/data-models';
import { ResourceNotFoundException } from '@aws-sdk/client-dynamodb';
import { Clock, getClock } from '../utils/clock';

export interface UserAuthorizationData {
  readonly accountIds?: userAccountIds;
  readonly allowedMcpTools: string[];
}

export class UserAccountMappingRepository extends AbstractRepository<UserAccountMapping> {
  protected readonly partitionKeyName = 'userId';
  protected readonly sortKeyName = ''; // this table does not have a sort key

  constructor(
    principal: string,
    tableName: string,
    dynamoDBClient: DynamoDBDocumentClient,
    private readonly clock: Clock = getClock(),
  ) {
    super(principal, tableName, dynamoDBClient);
  }

  /** Read a user's MCP grant. Missing/malformed fields fail closed to no tools. */
  async findUserAllowedMcpTools(userId: string): Promise<string[] | undefined> {
    return (await this.findUserAuthorization(userId))?.allowedMcpTools;
  }

  /**
   * Read one user's account assignments and MCP grant in a single request.
   *
   * The key is lowercased so callers do not have to canonicalize case. A record
   * written before this normalization existed may still be keyed by its
   * original case, so a lowercase miss falls back to the original-case key and,
   * on a hit, opportunistically re-keys the record to lowercase so the next read
   * finds it directly. The re-key is best-effort: if it fails, the read still
   * returns the data, and the fallback simply runs again next time.
   */
  async findUserAuthorization(userId: string): Promise<UserAuthorizationData | undefined> {
    const normalizedUserId = userId.toLowerCase();
    const response = await this.dynamoDBClient.send(
      new GetCommand({ TableName: this.tableName, Key: { [this.partitionKeyName]: normalizedUserId } }),
    );
    if (response.Item) {
      return this.toAuthorizationData(response.Item, userId);
    }

    // No lowercase record. A pre-normalization record may still exist under the
    // original case — retry that key before reporting the user as unknown.
    if (normalizedUserId === userId) return undefined;
    const originalCaseResponse = await this.dynamoDBClient.send(
      new GetCommand({ TableName: this.tableName, Key: { [this.partitionKeyName]: userId } }),
    );
    if (!originalCaseResponse.Item) return undefined;

    await this.reKeyToLowercase(userId, normalizedUserId, originalCaseResponse.Item);
    return this.toAuthorizationData(originalCaseResponse.Item, userId);
  }

  /**
   * Best-effort migration of a single mixed-case record to its lowercase key.
   *
   * Writes the item under the lowercase key (with the stored userId attribute
   * lowercased so key and attribute agree), then deletes the original-case
   * record. Any failure is swallowed and logged: re-keying is an optimization,
   * not a correctness requirement, and the original record is left intact so a
   * later read still finds it via the same fallback.
   */
  private async reKeyToLowercase(
    originalUserId: string,
    normalizedUserId: string,
    item: Record<string, unknown>,
  ): Promise<boolean> {
    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: { ...item, [this.partitionKeyName]: normalizedUserId },
        }),
      );
      await this.dynamoDBClient.send(
        new DeleteCommand({ TableName: this.tableName, Key: { [this.partitionKeyName]: originalUserId } }),
      );
      return true;
    } catch (error) {
      this.logger.warn('Could not re-key mixed-case user record to lowercase — read succeeded, will retry next time', {
        userId: originalUserId,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Resolve the partition key the user's record currently lives under, so a
   * subsequent update lands on the SAME item rather than upserting a second one.
   *
   * Returns the lowercase key for a record already stored (or freshly re-keyed)
   * there, and the original-case key only when a mixed-case record exists whose
   * re-key to lowercase FAILED — the case that made a blind lowercase write
   * create a partial duplicate. Returns the lowercase key when no record exists,
   * so a first-time write is normalized.
   */
  private async resolveWriteKey(userId: string): Promise<string> {
    const normalizedUserId = userId.toLowerCase();
    const normalizedRecord = await this.dynamoDBClient.send(
      new GetCommand({ TableName: this.tableName, Key: { [this.partitionKeyName]: normalizedUserId } }),
    );
    if (normalizedRecord.Item || normalizedUserId === userId) return normalizedUserId;

    const originalCaseRecord = await this.dynamoDBClient.send(
      new GetCommand({ TableName: this.tableName, Key: { [this.partitionKeyName]: userId } }),
    );
    if (!originalCaseRecord.Item) return normalizedUserId;

    // A mixed-case record exists. Try to migrate it; write to lowercase only if
    // that succeeded, otherwise write to the original-case key the record still
    // occupies so the update cannot orphan the other fields on a second item.
    const reKeyed = await this.reKeyToLowercase(userId, normalizedUserId, originalCaseRecord.Item);
    return reKeyed ? normalizedUserId : userId;
  }

  /**
   * Batch-read account assignments and MCP grants for a set of Cognito users.
   *
   * GET /users can return every user in the pool. Reading each mapping separately
   * creates one or two sequential DynamoDB requests per user, so this method uses
   * BatchGetItem's 100-key batches and the repository's unprocessed-key retry loop.
   *
   * The batch is keyed by the lowercased userId. A user whose record predates
   * that normalization is still keyed by its original case and so misses the
   * batch; for any such mixed-case miss this falls back to the single-key
   * {@link findUserAuthorization}, which retries the original case and re-keys it
   * to lowercase. The fallback is bounded to only the userIds that both differ in
   * case and were absent from the batch, so a pool of already-lowercase users
   * costs no extra reads.
   */
  async findUserAuthorizations(userIds: readonly string[]): Promise<Map<string, UserAuthorizationData>> {
    const normalizedUserIds = [...new Set(userIds.map((userId) => userId.toLowerCase()))];
    const result = await this.batchGetWithRetry<DynamoDBItem>(
      normalizedUserIds.map((userId) => ({ [this.partitionKeyName]: userId })),
      {
        requestItemOptions: {
          ProjectionExpression: 'userId, accountIds, allowedMcpTools',
        },
      },
    );

    const authorizations = new Map<string, UserAuthorizationData>();
    for (const item of result.items) {
      if (typeof item.userId !== 'string') {
        this.logger.warn('Ignoring user authorization record with no string userId');
        continue;
      }
      authorizations.set(item.userId.toLowerCase(), this.toAuthorizationData(item, item.userId));
    }

    // Fall back for mixed-case users the batch missed: their record may still be
    // keyed by the original case. Only original-case userIds that are absent from
    // the batch result are retried, so an all-lowercase pool adds no reads.
    const missingMixedCaseUserIds = [
      ...new Set(
        userIds.filter((userId) => userId !== userId.toLowerCase() && !authorizations.has(userId.toLowerCase())),
      ),
    ];
    for (const userId of missingMixedCaseUserIds) {
      const authorization = await this.findUserAuthorization(userId);
      if (authorization) {
        authorizations.set(userId.toLowerCase(), authorization);
      }
    }
    return authorizations;
  }

  /**
   * Replace a user's MCP grant without overwriting their account assignments.
   *
   * Writes to the key {@link resolveWriteKey} reports the record actually lives
   * under. DynamoDB's UpdateCommand upserts, so a blind lowercase write against a
   * record still stored under its original case (because a re-key attempt failed)
   * created a SECOND, partial item holding only the grant — leaving `accountIds`
   * orphaned on the original-case record, and the next read returned that partial
   * item, silently dropping every account assignment. Resolving the live key
   * first guarantees the update lands on the single existing item.
   */
  async putUserAllowedMcpTools(userId: string, allowedTools: readonly string[]): Promise<void> {
    const writeKey = await this.resolveWriteKey(userId);
    await this.dynamoDBClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { [this.partitionKeyName]: writeKey },
        UpdateExpression:
          'SET allowedMcpTools = :allowedMcpTools, lastModifiedBy = :lastModifiedBy, lastModifiedTimestamp = :lastModifiedTimestamp',
        ExpressionAttributeValues: {
          ':allowedMcpTools': [...allowedTools],
          ':lastModifiedBy': this.principal,
          ':lastModifiedTimestamp': this.clock.now().toISOString(),
        },
      }),
    );
  }

  /**
   * Set a user's account assignments, landing on the single record whatever key
   * case it is stored under (see {@link resolveWriteKey}).
   *
   * The API's updateAccountOperatorUser previously read and wrote this mapping
   * with the verbatim, possibly mixed-case userId while the read-authorization
   * path had migrated the record to lowercase — so the update hit a stale
   * original-case duplicate and authorization kept reading the lowercase record,
   * preserving accounts an administrator had just revoked. Routing the write
   * through here keeps assignment and authorization on the same item.
   */
  async setUserAccounts(userId: string, accountIds: userAccountIds, invitedBy: string): Promise<void> {
    const writeKey = await this.resolveWriteKey(userId);
    await this.dynamoDBClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { [this.partitionKeyName]: writeKey },
        UpdateExpression:
          'SET accountIds = :accountIds, invitedBy = if_not_exists(invitedBy, :invitedBy), ' +
          'invitationTimestamp = if_not_exists(invitationTimestamp, :invitationTimestamp), ' +
          'lastModifiedBy = :lastModifiedBy, lastModifiedTimestamp = :lastModifiedTimestamp',
        ExpressionAttributeValues: {
          ':accountIds': [...accountIds],
          ':invitedBy': invitedBy,
          ':invitationTimestamp': this.clock.now().toISOString(),
          ':lastModifiedBy': this.principal,
          ':lastModifiedTimestamp': this.clock.now().toISOString(),
        },
      }),
    );
  }

  async getUserAccounts(userId: string): Promise<userAccountIds | undefined> {
    // Routed through findUserAuthorization, not findById: findById swallows every
    // error and returns undefined, which makes a transient DynamoDB failure
    // indistinguishable from "user not found". Callers that authorize on the
    // result (the MCP server) need a transient failure to propagate so they can
    // surface it as retryable rather than treat it as "no accounts". This path
    // also inherits the mixed-case original-key fallback.
    const authorization = await this.findUserAuthorization(userId);
    if (!authorization) {
      this.logger.warn(
        `Could not find user account mapping for user ${userId} in table ${this.tableName}. This user should be removed and re-invited if necessary.`,
      );
      return undefined;
    }
    return authorization.accountIds;
  }

  async create(userAccountMapping: UserAccountMapping): Promise<void> {
    await this.put(userAccountMapping);
  }

  /** Scans the table and returns all userId values (email addresses). */
  async findAllUserIds(): Promise<string[]> {
    return this.findAllWithTransform(
      (item) => {
        const userId = item.userId;
        if (typeof userId !== 'string') {
          throw new TypeError(`Expected userId to be a string, got ${typeof userId}`);
        }
        return userId;
      },
      {
        ProjectionExpression: 'userId',
      },
    );
  }

  /**
   * Delete a user's authorization record, whichever key case it is stored under.
   *
   * Reads and grant writes normalize the key to lowercase, but records written
   * before that normalization are still keyed by their original case, and
   * `deleteUser` passes the path id verbatim. Deleting only the supplied key
   * therefore left the other form behind — including the record holding
   * `allowedMcpTools` — so re-inviting the same address restored a stale grant
   * the administrator believed had been removed. Both forms are deleted, and a
   * key that does not exist is a no-op, so this stays idempotent.
   */
  async deleteIfExists(userId: string, _: string): Promise<void> {
    const keysToDelete = [...new Set([userId, userId.toLowerCase()])];
    try {
      for (const key of keysToDelete) {
        await this.dynamoDBClient.send(
          new DeleteCommand({
            TableName: this.tableName,
            Key: {
              [this.partitionKeyName]: key,
            },
          }),
        );
      }
    } catch (error) {
      if (error instanceof ResourceNotFoundException) {
        this.logger.debug(
          `Could not find user account mapping to delete for user ${userId} in table ${this.tableName}.`,
        );
        return;
      }
      throw error;
    }
  }

  override async put(item: UserAccountMapping): Promise<void> {
    const itemWithTimestamp = {
      ...item,
      lastModifiedBy: this.principal,
      lastModifiedTimestamp: new Date().toISOString(),
    };
    return await super.putUntyped(itemWithTimestamp);
  }

  override async findById(userId: string, _: string): Promise<UserAccountMapping | undefined> {
    try {
      const params = {
        TableName: this.tableName,
        Key: {
          [this.partitionKeyName]: userId,
        },
      };

      const response = await this.dynamoDBClient.send(new GetCommand(params));
      const item = response.Item;

      if (!item) {
        return undefined;
      }

      delete (item as any).lastUpdatedBy;
      return item as UserAccountMapping;
    } catch (error) {
      this.logger.debug('Could not find item by ID', { partitionKey: userId });
      return undefined;
    }
  }

  private toAuthorizationData(item: Record<string, unknown>, userId: string): UserAuthorizationData {
    const allowedTools = item.allowedMcpTools;
    const hasValidAllowedTools = Array.isArray(allowedTools) && allowedTools.every((tool) => typeof tool === 'string');
    const allowedMcpTools = hasValidAllowedTools ? allowedTools : [];
    if (!hasValidAllowedTools && allowedTools !== undefined) {
      this.logger.warn('Denying all tools for malformed user MCP grant — repair required', { userId });
    }

    const accountIds = item.accountIds;
    return {
      allowedMcpTools,
      ...(Array.isArray(accountIds) && accountIds.every((accountId) => typeof accountId === 'string')
        ? { accountIds: accountIds as userAccountIds }
        : {}),
    };
  }
}
