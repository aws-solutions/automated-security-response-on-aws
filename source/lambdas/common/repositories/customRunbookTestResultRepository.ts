// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, GetCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import type { RunbookTestResult } from '@asr/data-models';

/**
 * DynamoDB access for recording a custom-runbook version's test outcome, and
 * for the pre-check that confirms the version is registered.
 *
 * ADR 0003 keeps DynamoDB query construction out of business logic. The
 * `test_runbook_yaml` executor owns the decision of WHAT to record (PASSED vs
 * FAILED, the digest binding, the reasons surfaced to the caller); this
 * repository owns HOW it touches the table — the projected consistent read and
 * the guarded conditional write — so the executor holds no `GetCommand` /
 * `UpdateCommand` of its own.
 */

/** The registration fields the test pre-check reads for a version. */
export interface RegisteredRunbookVersion {
  readonly runbookId: string;
  readonly version: number;
  /** sha256 of the registered YAML, or undefined for a pre-digest legacy record. */
  readonly registeredContentDigest: string | undefined;
}

export class CustomRunbookTestResultRepository {
  constructor(
    private readonly tableName: string,
    private readonly dynamoDBClient: DynamoDBDocumentClient,
  ) {}

  /**
   * Read the registration fields for a (runbookId, version), or undefined when
   * no such version exists.
   *
   * `find` (not `get`): a missing version is a normal, caller-facing outcome the
   * executor turns into a specific ValidationError, not an exception here. Reads
   * consistently and projects only the fields the pre-check needs.
   */
  async findRegisteredVersion(runbookId: string, version: number): Promise<RegisteredRunbookVersion | undefined> {
    const response = await this.dynamoDBClient.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { runbookId, version },
        ProjectionExpression: 'runbookId, #v, registeredContentDigest',
        ExpressionAttributeNames: { '#v': 'version' },
        ConsistentRead: true,
      }),
    );
    if (!response.Item) return undefined;

    const registeredContentDigest = response.Item.registeredContentDigest;
    return {
      runbookId,
      version,
      registeredContentDigest: typeof registeredContentDigest === 'string' ? registeredContentDigest : undefined,
    };
  }

  /**
   * Record a version's test outcome under two guards applied atomically: the
   * version must already be registered, and the just-tested YAML must be the
   * YAML registered for it (`registeredContentDigest = result.testedContentDigest`).
   *
   * Throws the raw DynamoDB error on failure — notably
   * `ConditionalCheckFailedException`, which the caller inspects (it requests
   * `ALL_OLD`, so the pre-write item is attached) to tell "not registered" apart
   * from "digest mismatch". The classification stays with the caller because the
   * messages are user-facing tool output, not persistence concerns.
   */
  async recordTestResult(runbookId: string, version: number, result: RunbookTestResult): Promise<void> {
    // `testError` is `string | undefined`. On a pass (no error) REMOVE the attribute rather
    // than writing a DynamoDB NULL: NULL is neither `string` nor absent, so a reader typed
    // against `string | undefined` would see a value the type forbids, and a stale failure
    // reason must be cleared, not replaced with null. On a failure, SET it.
    const setFields = [
      'testStatus = :status',
      'testedAt = :testedAt',
      'testAccountId = :accountId',
      'testedContentDigest = :digest',
      'testedIamActions = :iamActions',
      'testRoleArn = :testRoleArn',
    ];
    const hasError = result.testError !== undefined;
    const updateExpression = hasError
      ? `SET ${[...setFields, 'testError = :error'].join(', ')}`
      : `SET ${setFields.join(', ')} REMOVE testError`;

    await this.dynamoDBClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { runbookId, version },
        // `version` is a DynamoDB reserved word, so the condition refers to it
        // through an ExpressionAttributeNames alias rather than by name.
        UpdateExpression: updateExpression,
        // Two guards in one atomic write:
        //  1. The version must already be registered — otherwise an unregistered
        //     (runbookId, version) pair would be created as a bare record carrying
        //     nothing but a passing test.
        //  2. The YAML just tested must be the YAML registered for this version.
        //     Testing something else and recording a pass against version N would
        //     let unproven bytes deploy.
        ConditionExpression:
          'attribute_exists(runbookId) AND attribute_exists(#v) AND registeredContentDigest = :digest',
        ExpressionAttributeNames: { '#v': 'version' },
        ExpressionAttributeValues: {
          ':status': result.testStatus,
          ':testedAt': result.testedAt,
          ':accountId': result.testAccountId,
          ':digest': result.testedContentDigest,
          ':iamActions': result.testedIamActions,
          ':testRoleArn': result.testRoleArn,
          // Only bound when SET-ing an error; a passing test REMOVEs the attribute instead.
          ...(hasError ? { ':error': result.testError } : {}),
        },
        // Lets a failed condition be attributed to the right guard instead of
        // reporting "not registered" for a digest mismatch.
        ReturnValuesOnConditionCheckFailure: 'ALL_OLD',
      }),
    );
  }
}
