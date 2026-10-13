// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import {
  CUSTOM_RUNBOOK_CONTROL_STATUS_GSI,
  MemberDeploymentState,
  RunbookId,
  RunbookMetadata,
  RunbookStatus,
} from '@asr/data-models';
import { AbstractRepository, DynamoDBKey } from './abstractRepository';
import { ConflictError, NotFoundError } from '../utils/httpErrors';

/** Thrown when a conditional create loses the race for a (runbookId, version) slot. */
export class RunbookVersionConflictError extends ConflictError {
  constructor(runbookId: string, version: number) {
    super(`Version ${version} already exists for runbook ${runbookId}`);
    this.name = 'RunbookVersionConflictError';
  }
}

/**
 * The attributes of a DEPLOYED runbook version that the controls list needs.
 *
 * Deliberately narrower than `RunbookMetadata`: it is exactly what
 * `findDeployedVersions` projects, so the type cannot promise fields that query
 * does not read.
 */
export interface DeployedRunbookControl {
  runbookId: RunbookId;
  version: number;
  controlId: string;
  description: string;
  createdAt: string;
  createdBy: string;
  /**
   * When this version was last deployed. Selection of the live version orders by this,
   * not by version number, because a rollback re-deploys an older version — the version
   * running is the one deployed most recently. May be absent on records that predate the
   * attribute, in which case createdAt is the recency fallback.
   */
  deployedAt?: string;
}

/**
 * Map one projected scan item onto the interface the controls list consumes.
 *
 * Written field by field rather than cast so the ProjectionExpression in
 * `findDeployedVersions` and this interface cannot drift apart unnoticed: adding a
 * field to `DeployedRunbookControl` without projecting it fails to compile here,
 * which is the direction a plain `item as unknown as DeployedRunbookControl` hid.
 * The per-field casts are the DynamoDB deserialization boundary (ADR 0003), and the
 * `RunbookId` cast is the branded-id boundary ADR 0006 sanctions.
 */
function toDeployedRunbookControl(item: Record<string, unknown>): DeployedRunbookControl {
  return {
    runbookId: item.runbookId as RunbookId,
    version: item.version as number,
    controlId: item.controlId as string,
    description: item.description as string,
    createdAt: item.createdAt as string,
    createdBy: item.createdBy as string,
    deployedAt: item.deployedAt as string | undefined,
  };
}

export class CustomRunbookRepository extends AbstractRepository<RunbookMetadata> {
  protected readonly partitionKeyName = 'runbookId';
  protected readonly sortKeyName = 'version';
  protected override readonly GSI_KEY_STRUCTURES: Record<string, string[]> = {
    [CUSTOM_RUNBOOK_CONTROL_STATUS_GSI]: ['controlId', 'status'],
  };

  constructor(tableName: string, dynamoDBClient: DynamoDBDocumentClient) {
    super('CustomRunbookRepository', tableName, dynamoDBClient);
  }

  /**
   * Find the latest version of a Custom Runbook, querying with ScanIndexForward=false and
   * Limit=1. A consistent read is used because the forward case — register a new version,
   * then deploy it (the common path, which resolves the latest here) — must see the version
   * register just wrote, the same race findVersion guards for a named rollback version.
   */
  async findLatestVersion(runbookId: RunbookId): Promise<RunbookMetadata | undefined> {
    const response = await this.dynamoDBClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'runbookId = :pk',
        ExpressionAttributeValues: { ':pk': runbookId },
        ScanIndexForward: false,
        Limit: 1,
        ConsistentRead: true,
      }),
    );
    return response.Items?.[0] as RunbookMetadata | undefined;
  }

  /**
   * Find one specific version of a Custom Runbook.
   *
   * Deploy uses this when a caller names a `version` — the documented rollback
   * mechanism — so an older version can be released without first becoming the
   * latest. A consistent read is used because a deploy immediately following a
   * register must see the version that register just wrote.
   */
  async findVersion(runbookId: RunbookId, version: number): Promise<RunbookMetadata | undefined> {
    const response = await this.dynamoDBClient.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { runbookId, version },
        ConsistentRead: true,
      }),
    );
    return response.Item as RunbookMetadata | undefined;
  }

  /**
   * Every version record for a runbook, oldest to newest, following pagination.
   *
   * Register uses this to stage the next version's `deployedAccounts` from the fleet's
   * actual current state rather than from the single numerically-latest record. A rollback
   * (deploying an older version) clears accounts off the higher-numbered records, so the
   * highest version's map can legitimately be empty while the fleet runs an older version;
   * reading only that record would stage the new version with no accounts. A consistent
   * read is used because a register may immediately follow a deploy that just moved accounts.
   */
  async findAllVersions(runbookId: RunbookId): Promise<RunbookMetadata[]> {
    const items: RunbookMetadata[] = [];
    let exclusiveStartKey: DynamoDBKey | undefined;
    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'runbookId = :pk',
          ExpressionAttributeValues: { ':pk': runbookId },
          ConsistentRead: true,
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      items.push(...((response.Items ?? []) as RunbookMetadata[]));
      exclusiveStartKey = response.LastEvaluatedKey as DynamoDBKey | undefined;
    } while (exclusiveStartKey);
    return items;
  }

  /**
   * Find all Custom Runbook versions for a given control ID via GSI.
   *
   * Loops over `lastEvaluatedKey` so every version is returned even when a
   * control's versioned records exceed one 1MB DynamoDB page. Without the loop,
   * later versions would be silently dropped and `loadCustomRunbookSummaries`
   * (which collapses to the latest version) could report a stale latest.
   */
  async findByControlId(controlId: string): Promise<RunbookMetadata[]> {
    const items: RunbookMetadata[] = [];
    let exclusiveStartKey: DynamoDBKey | undefined;
    do {
      const result = await this.queryIndexPK({
        indexName: CUSTOM_RUNBOOK_CONTROL_STATUS_GSI,
        partitionKeyName: 'controlId',
        partitionKeyValue: controlId,
        exclusiveStartKey,
      });
      items.push(...result.items);
      exclusiveStartKey = result.lastEvaluatedKey;
    } while (exclusiveStartKey);
    return items;
  }

  /**
   * The DEPLOYED versions of every custom runbook, projected down to the
   * attributes the controls list consumes.
   *
   * `getAllControls` runs on every controls-list request, so this exists instead
   * of reusing `findAll()`: the filter drops DRAFT versions and the projection
   * drops the S3 pointers, per-account deployment state and deploy metadata, so
   * the returned payload is proportional to the number of deployed runbooks
   * rather than to every version ever registered.
   *
   * It is still a `Scan`, and DynamoDB applies `FilterExpression` after the read,
   * so consumed read capacity scales with the whole table — the same tradeoff
   * `UserAccountMappingRepository.listClientAllowlists` documents, accepted for
   * the same reason (custom runbooks are human-authored, so the table stays
   * small). The `controlId-status` GSI cannot replace this: it partitions on
   * `controlId`, so it can answer "is this control deployed?" but not "which
   * controls are deployed?". Making that a `Query` needs an index partitioned on
   * status, which is a table-schema change owned by the infra work rather than
   * this API-only change.
   */
  async findDeployedVersions(): Promise<DeployedRunbookControl[]> {
    const deployedStatus: RunbookStatus = 'DEPLOYED';
    return this.findAllWithTransform(toDeployedRunbookControl, {
      FilterExpression: '#status = :deployed',
      // status, version and description are all DynamoDB reserved words.
      ProjectionExpression: 'runbookId, #version, controlId, #description, createdAt, createdBy, deployedAt',
      ExpressionAttributeNames: { '#status': 'status', '#version': 'version', '#description': 'description' },
      ExpressionAttributeValues: { ':deployed': deployedStatus },
    });
  }

  /** Scan all Custom Runbook records. Use sparingly — prefer findByControlId for filtered queries. */
  async findAll(): Promise<RunbookMetadata[]> {
    // This is the DynamoDB deserialization boundary (ADR 0003): the SDK hands back
    // an untyped `Record<string, unknown>`, and these records are written only by
    // this repository, so the stored shape is trusted rather than re-validated.
    // The `unknown` bridge is required — TypeScript rejects a direct
    // `Record<string, unknown> as RunbookMetadata` (branded RunbookId + required
    // fields don't overlap). Validating instead would mean either silently
    // dropping a trusted record or failing the whole controls list on one bad row.
    //
    // Unlike findDeployedVersions this reads whole records, so there is no
    // projection that could drift away from the interface; the field-by-field
    // mapping that guards that case would only restate every attribute here.
    return this.findAllWithTransform((item) => item as unknown as RunbookMetadata);
  }

  /**
   * Atomically create a specific (runbookId, version) record. Fails with
   * RunbookVersionConflictError if that version already exists, so two concurrent
   * registers can never silently overwrite each other — the loser retries with
   * the next version number. This is the conditional-write guard for the
   * versioned authoring lifecycle.
   */
  async createVersion(metadata: RunbookMetadata): Promise<void> {
    try {
      await this.dynamoDBClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: metadata,
          // `version` is a DynamoDB reserved word, so it must be aliased even inside
          // attribute_not_exists — real DynamoDB raises ValidationException on the
          // bare word (DynamoDB Local is lenient and would mask it).
          ConditionExpression: 'attribute_not_exists(runbookId) AND attribute_not_exists(#version)',
          ExpressionAttributeNames: { '#version': 'version' },
        }),
      );
    } catch (error) {
      if (error instanceof Error && error.name === 'ConditionalCheckFailedException') {
        throw new RunbookVersionConflictError(metadata.runbookId, metadata.version);
      }
      throw error;
    }
  }

  /**
   * Record one member account's deployment state on a specific runbook version.
   *
   * Written per account rather than as a whole-map replacement so that two
   * accounts being released concurrently cannot clobber each other's entry, and
   * so a failure in one account leaves every other account's state untouched.
   *
   * The parent map is created first with `if_not_exists` because a single
   * UpdateExpression may not both create `deployedAccounts` and set a path
   * inside it — DynamoDB rejects overlapping document paths.
   */
  async recordMemberDeployment(
    runbookId: RunbookId,
    version: number,
    accountId: string,
    state: MemberDeploymentState,
  ): Promise<void> {
    try {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { runbookId, version },
          UpdateExpression: 'SET deployedAccounts = if_not_exists(deployedAccounts, :empty)',
          ExpressionAttributeValues: { ':empty': {} },
          ConditionExpression: 'attribute_exists(runbookId)',
        }),
      );

      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { runbookId, version },
          UpdateExpression: 'SET deployedAccounts.#account = :state',
          ExpressionAttributeNames: { '#account': accountId },
          ExpressionAttributeValues: { ':state': state },
          ConditionExpression: 'attribute_exists(runbookId)',
        }),
      );
    } catch (error) {
      throw this.mapMissingRecord(error, runbookId, version);
    }
  }

  /**
   * Remove an account's entry from every version record except the one it now runs.
   *
   * `deployedAccounts` is a per-version map, and `stageAccountsForNewVersion` copies the
   * whole fleet forward onto each new version at register time. So after an account is
   * released to version N, its entry still lingers on every OTHER version's map with a
   * stale `runbookVersion`. Left there, a later read of one of those records — a rollback
   * that re-deploys an older version, say — counts that account as running the older
   * version it no longer runs, and reports the fleet consistent when it is not. Clearing
   * the account everywhere but `keepVersion` keeps each account in exactly one version's
   * map: the version it actually runs. Best-effort per record and idempotent — removing an
   * absent key is a no-op — so a stray failure cannot fail the deploy that already
   * succeeded.
   */
  async clearAccountFromOtherVersions(runbookId: RunbookId, keepVersion: number, accountId: string): Promise<void> {
    // Page through every version: a single Query returns only the first 1MB page, so a
    // runbook with enough versions to span pages would leave the account's stale entry on the
    // unread ones — the very stale-record drift this method exists to remove.
    const otherVersions: number[] = [];
    let exclusiveStartKey: DynamoDBKey | undefined;
    do {
      const response = await this.dynamoDBClient.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'runbookId = :pk',
          ExpressionAttributeValues: { ':pk': runbookId },
          ProjectionExpression: '#version',
          ExpressionAttributeNames: { '#version': 'version' },
          ExclusiveStartKey: exclusiveStartKey,
        }),
      );
      for (const item of response.Items ?? []) {
        const version = item.version as number;
        if (version !== keepVersion) otherVersions.push(version);
      }
      exclusiveStartKey = response.LastEvaluatedKey as DynamoDBKey | undefined;
    } while (exclusiveStartKey);

    for (const version of otherVersions) {
      // Per-record best-effort: one record concurrently deleted (ConditionalCheckFailed) or a
      // transient error must not abort clearing the rest, or the account's stale entry would
      // linger on every version after the failing one — the drift this method removes. The
      // deploy has already succeeded, so a failure here only degrades to the stale-count bug.
      try {
        await this.dynamoDBClient.send(
          new UpdateCommand({
            TableName: this.tableName,
            Key: { runbookId, version },
            UpdateExpression: 'REMOVE deployedAccounts.#account',
            ExpressionAttributeNames: { '#account': accountId },
            ConditionExpression: 'attribute_exists(runbookId)',
          }),
        );
      } catch (error) {
        this.logger.warn('Could not clear a released account from one runbook version', {
          runbookId,
          version,
          accountId,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
  private mapMissingRecord(error: unknown, runbookId: RunbookId, version: number): Error {
    if (error instanceof Error && error.name === 'ConditionalCheckFailedException') {
      return new NotFoundError(`Custom Runbook version not found: ${runbookId} v${version}`);
    }
    return error instanceof Error ? error : new Error(String(error));
  }

  /** Delete a specific (runbookId, version) record. Used as a compensating action when S3 upload fails after DynamoDB write. */
  async deleteVersion(runbookId: RunbookId, version: number): Promise<void> {
    await this.dynamoDBClient.send(
      new DeleteCommand({
        TableName: this.tableName,
        Key: { runbookId, version },
      }),
    );
  }

  /** Update a Custom Runbook's lifecycle status and optional additional fields. */
  async updateStatus(
    runbookId: RunbookId,
    version: number,
    status: RunbookStatus,
    updateFields?: Partial<RunbookMetadata>,
  ): Promise<void> {
    const expressionParts = ['#status = :status'];
    const expressionAttributeNames: Record<string, string> = { '#status': 'status' };
    const expressionAttributeValues: Record<string, unknown> = { ':status': status };

    // Alias each extra field by its own name (a valid expression-attribute-name
    // token for these camelCase keys), so there is no parallel index to keep in
    // sync between the three structures.
    for (const [key, value] of Object.entries(updateFields ?? {})) {
      if (key === 'runbookId' || key === 'version' || key === 'status') continue;
      expressionParts.push(`#${key} = :${key}`);
      expressionAttributeNames[`#${key}`] = key;
      expressionAttributeValues[`:${key}`] = value;
    }

    try {
      await this.dynamoDBClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { runbookId, version },
          UpdateExpression: `SET ${expressionParts.join(', ')}`,
          ExpressionAttributeNames: expressionAttributeNames,
          ExpressionAttributeValues: expressionAttributeValues,
          ConditionExpression: 'attribute_exists(runbookId)',
        }),
      );
    } catch (error) {
      throw this.mapMissingRecord(error, runbookId, version);
    }
  }
}
