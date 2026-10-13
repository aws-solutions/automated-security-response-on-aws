// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { createHash } from 'node:crypto';
import { GetObjectCommand, GetObjectCommandOutput, NoSuchKey, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  CreateRoleCommand,
  GetRoleCommand,
  IAMClient,
  NoSuchEntityException,
  PutRolePolicyCommand,
  TagRoleCommand,
} from '@aws-sdk/client-iam';
import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import {
  CreateDocumentCommand,
  GetParameterCommand,
  ListDocumentsCommand,
  ParameterNotFound,
  SSMClient,
  UpdateDocumentDefaultVersionCommand,
} from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { DeployRunbookResult, RunbookId, RunbookTestResult } from '@asr/data-models';
import { mockClient } from 'aws-sdk-client-mock';
import { RunbookDeploymentService } from '../../services/runbookDeploymentService';
import { CustomRunbookTestResultRepository } from '../../../common/repositories/customRunbookTestResultRepository';
import { CustomRunbookRepository } from '../../../common/repositories/customRunbookRepository';
import { resetApiLambdaEnvironmentCache } from '../../apiLambdaEnvironment';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { customRunbookTableName } from '../../../common/__tests__/envSetup';
import type { Clock } from '../../../common/utils/clock';
import type { IdGenerator } from '../../../common/utils/idGenerator';

// Flow-level suite for the custom remediation lifecycle: register → test → deploy
// → re-register → rollback, driven as ONE sequence against shared state rather
// than as independent single-call tests.
//
// Why the shared state matters: every guarantee this suite checks is a property
// BETWEEN calls (the deploy gate reads what the test recording wrote; a rollback
// reads what an earlier register stored), so a per-call stub proves nothing. The
// runbook table is DynamoDB Local (ADR 0002/0003) and the runbook bucket is an
// in-memory object store, both persisting across steps within a test. AWS calls
// with no bearing on the lifecycle invariants (STS/IAM/SSM) are mocked at the SDK
// boundary and always succeed, so a failure here is a lifecycle defect and not an
// infrastructure simulation artifact.

const stsMock = mockClient(STSClient);
const iamMock = mockClient(IAMClient);
const ssmMock = mockClient(SSMClient);
const s3Mock = mockClient(S3Client);

const NOW = '2026-01-01T00:00:00.000Z';
const fixedClock: Clock = { now: () => new Date(NOW) };

const CONTROL_ID = 'S3.9';
const BUCKET_NAME = 'test-custom-runbook-bucket';
const ACCOUNT_A = '111111111111';
const IAM_ACTIONS = ['s3:PutBucketLogging'];

const V1_YAML = 'schemaVersion: "0.3"\ndescription: v1 enables access logging\n';
const V2_YAML = 'schemaVersion: "0.3"\ndescription: v2 enables access logging\n';
/** Stands in for YAML a caller substitutes after earning a passing test. */
const TAMPERED_YAML = 'schemaVersion: "0.3"\ndescription: grants itself administrator\n';

function sha256(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * The runbook bucket, as an in-memory store keyed by S3 key.
 *
 * Register writes into it through the mocked PutObject and deploy reads back
 * through the mocked GetObject, so the artifact a deploy installs is the artifact
 * an earlier register actually stored. `overwriteStoredArtifact` then models the
 * one thing a per-call stub cannot: object bytes diverging from the metadata that
 * describes them.
 */
class RunbookObjectStore {
  private readonly objects = new Map<string, string>();

  put(key: string, body: string): void {
    this.objects.set(key, body);
  }

  get(key: string): string | undefined {
    return this.objects.get(key);
  }

  delete(key: string): void {
    this.objects.delete(key);
  }

  reset(): void {
    this.objects.clear();
  }
}

const objectStore = new RunbookObjectStore();

/**
 * Drives one custom remediation lifecycle against shared state.
 *
 * `recordPassingTest` stands in for the recording half of `test_runbook_yaml`:
 * that tool executes the caller-supplied YAML in a transient document and then
 * records the outcome with the MCP server's own role, digest-bound to the YAML it
 * ran. The transient execution is out of scope here (covered by
 * testRunbookYaml.test.ts); what this suite needs is the recording, because that
 * is the input the deploy gate reads.
 */
class LifecycleHarness {
  private readonly deploymentService: RunbookDeploymentService;
  private readonly testResultRepository: CustomRunbookTestResultRepository;

  constructor(documentClient: DynamoDBDocumentClient) {
    this.deploymentService = new RunbookDeploymentService(new Logger({ serviceName: 'test' }), fixedClock, {
      randomUUID: () => 'runbook-under-test',
    } as IdGenerator);
    this.testResultRepository = new CustomRunbookTestResultRepository(customRunbookTableName, documentClient);
  }

  async register(runbookYaml: string, runbookId?: RunbookId): Promise<DeployRunbookResult> {
    return this.deploymentService.execute(
      {
        action: 'register',
        runbook_yaml: runbookYaml,
        control_id: CONTROL_ID,
        ...(runbookId ? { runbook_id: runbookId } : {}),
      },
      'operator@example.com',
    );
  }

  /** Record the outcome `test_runbook_yaml` would write for `yamlUnderTest`. */
  async recordTest(
    runbookId: RunbookId,
    version: number,
    yamlUnderTest: string,
    overrides: Partial<RunbookTestResult> = {},
  ): Promise<void> {
    await this.testResultRepository.recordTestResult(runbookId, version, {
      testStatus: 'PASSED',
      testedAt: NOW,
      testAccountId: ACCOUNT_A,
      testedContentDigest: sha256(yamlUnderTest),
      testedIamActions: [...IAM_ACTIONS],
      testRoleArn: `arn:aws:iam::${ACCOUNT_A}:role/SO0111-Remediate-Custom-Test-abc`,
      ...overrides,
    });
  }

  async deploy(runbookId: RunbookId, version?: number): Promise<DeployRunbookResult> {
    return this.deploymentService.execute(
      {
        action: 'deploy',
        runbook_id: runbookId,
        control_id: CONTROL_ID,
        security_standard: 'SC',
        standard_version: '2.0.0',
        required_iam_actions: [...IAM_ACTIONS],
        member_account_ids: [ACCOUNT_A],
        ...(version === undefined ? {} : { version }),
      },
      'operator@example.com',
    );
  }

  /**
   * Replace a stored artifact's bytes while leaving every DynamoDB digest intact —
   * the state reached by any write to the bucket that does not go through register.
   */
  overwriteStoredArtifact(s3Key: string, runbookYaml: string): void {
    objectStore.put(s3Key, runbookYaml);
  }

  /**
   * Drop a stored artifact while leaving its DynamoDB metadata in place — the state
   * reached if the object is deleted or its upload was lost after the record was written.
   */
  removeStoredArtifact(s3Key: string): void {
    objectStore.delete(s3Key);
  }
}

/** The YAML content each member-account document was installed with, in call order. */
function installedMemberDocumentContents(): string[] {
  return ssmMock
    .commandCalls(CreateDocumentCommand)
    .filter((call) => !!call.args[0].input.Tags)
    .map((call) => call.args[0].input.Content ?? '');
}

describe('Custom remediation lifecycle (flow)', () => {
  let documentClient: DynamoDBDocumentClient;
  let harness: LifecycleHarness;

  beforeAll(async () => {
    await DynamoDBTestSetup.initialize();
    documentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createCustomRunbookTable(customRunbookTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(customRunbookTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(customRunbookTableName, 'customRunbook');
    stsMock.reset();
    iamMock.reset();
    ssmMock.reset();
    s3Mock.reset();
    objectStore.reset();

    stsMock.on(AssumeRoleCommand).resolves({
      Credentials: { AccessKeyId: 'ak', SecretAccessKey: 'sk', SessionToken: 'st', Expiration: new Date() },
    });
    iamMock.on(GetRoleCommand).rejects(new NoSuchEntityException({ message: 'not found', $metadata: {} }));
    iamMock.on(CreateRoleCommand).resolves({});
    iamMock.on(PutRolePolicyCommand).resolves({});
    iamMock.on(TagRoleCommand).resolves({});

    ssmMock.on(GetParameterCommand).rejects(new ParameterNotFound({ message: 'no control remap', $metadata: {} }));
    ssmMock.on(ListDocumentsCommand).resolves({ DocumentIdentifiers: [] });
    ssmMock.on(CreateDocumentCommand).resolves({ DocumentDescription: { DocumentVersion: '1' } });
    ssmMock.on(UpdateDocumentDefaultVersionCommand).resolves({});

    s3Mock.on(PutObjectCommand).callsFake(async (input) => {
      objectStore.put(String(input.Key), String(input.Body));
      return {};
    });
    s3Mock.on(GetObjectCommand).callsFake(async (input) => {
      const body = objectStore.get(String(input.Key));
      // Real S3 throws NoSuchKey for a missing object rather than returning an empty body, so
      // the "artifact is gone" path exercises the service's actual catch, not a synthetic case.
      if (body === undefined) throw new NoSuchKey({ message: 'not found', $metadata: {} });
      return {
        Body: { transformToString: () => Promise.resolve(body) } as unknown as GetObjectCommandOutput['Body'],
      };
    });

    process.env.CUSTOM_RUNBOOK_BUCKET_NAME = BUCKET_NAME;
    process.env.CUSTOM_RUNBOOK_TABLE_NAME = customRunbookTableName;
    resetApiLambdaEnvironmentCache();

    harness = new LifecycleHarness(documentClient);
  });

  describe('test-before-deploy gate', () => {
    it('deploys a version whose registered content passed testing', async () => {
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);

      const deployed = await harness.deploy(runbookId);

      expect(deployed.status).toBe('DEPLOYED');
      expect(deployed.version).toBe(1);
      expect(installedMemberDocumentContents()).toEqual([V1_YAML]);
    });

    it('rejects a version that was never tested', async () => {
      const registered = await harness.register(V1_YAML);

      await expect(harness.deploy(registered.runbook_id)).rejects.toThrow(/recorded test status is untested/);
      expect(installedMemberDocumentContents()).toEqual([]);
    });

    it('rejects a version whose test failed', async () => {
      const registered = await harness.register(V1_YAML);
      await harness.recordTest(registered.runbook_id, 1, V1_YAML, { testStatus: 'FAILED' });

      await expect(harness.deploy(registered.runbook_id)).rejects.toThrow(/recorded test status is FAILED/);
      expect(installedMemberDocumentContents()).toEqual([]);
    });

    it('rejects a deploy whose requested IAM actions differ from the tested set', async () => {
      const registered = await harness.register(V1_YAML);
      await harness.recordTest(registered.runbook_id, 1, V1_YAML, { testedIamActions: ['s3:GetBucketLogging'] });

      await expect(harness.deploy(registered.runbook_id)).rejects.toThrow(/requested IAM actions do not match/);
      expect(installedMemberDocumentContents()).toEqual([]);
    });

    it('rejects a newly registered version that inherits no test result from its predecessor', async () => {
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);
      await harness.deploy(runbookId);

      await harness.register(V2_YAML, runbookId);

      await expect(harness.deploy(runbookId)).rejects.toThrow(/cannot be deployed/);
    });

    it('rejects a deploy whose stored artifact no longer matches the content that passed testing', async () => {
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);

      // The gate compares two DynamoDB digests to each other. Swapping only the
      // stored object leaves both untouched, so nothing in the metadata reflects
      // that the bytes about to be installed were never tested.
      harness.overwriteStoredArtifact(registered.s3_key as string, TAMPERED_YAML);

      await expect(harness.deploy(runbookId)).rejects.toThrow(/does not match/);
      expect(installedMemberDocumentContents()).toEqual([]);
    });

    it('refuses to deploy a version whose stored artifact is gone, without naming the bucket', async () => {
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);

      harness.removeStoredArtifact(registered.s3_key as string);

      // The caller learns the content is unreadable and what to do about it; the bucket
      // and key stay in the logs, since the response must not describe backend storage.
      const deploy = harness.deploy(runbookId);
      await expect(deploy).rejects.toThrow(/stored content for this runbook version could not be read/);
      await expect(deploy).rejects.not.toThrow(new RegExp(BUCKET_NAME));
      expect(installedMemberDocumentContents()).toEqual([]);
    });
  });

  describe('version rollback', () => {
    it('installs the named older version rather than the latest', async () => {
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);
      await harness.deploy(runbookId);

      await harness.register(V2_YAML, runbookId);
      await harness.recordTest(runbookId, 2, V2_YAML);
      await harness.deploy(runbookId);

      ssmMock.resetHistory();
      const rolledBack = await harness.deploy(runbookId, 1);

      expect(rolledBack.version).toBe(1);
      expect(installedMemberDocumentContents()).toEqual([V1_YAML]);
    });

    it('reconstructs the member fleet on the next register after a rollback', async () => {
      // Regression: v1 → v2 → rollback-to-v1 clears the account off v2's map (cleanup keeps
      // each account on exactly the version it runs), so v2 — the numerically-highest record —
      // has an empty fleet while the fleet actually runs v1. Registering v3 must merge across
      // ALL version records to recover the fleet; reading only the latest record would stage
      // v3 with zero accounts. Exercised end-to-end against DynamoDB Local so the real query,
      // cleanup writes, and merge are validated, not a hand-authored client fixture.
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);
      await harness.deploy(runbookId);

      await harness.register(V2_YAML, runbookId);
      await harness.recordTest(runbookId, 2, V2_YAML);
      await harness.deploy(runbookId);

      // Roll back to v1: the account is re-pinned to v1 and cleared from v2.
      await harness.deploy(runbookId, 1);

      // Registering v3 stages the fleet from the version each account actually runs (v1),
      // even though the latest record (v2) is now empty.
      await harness.register(V2_YAML, runbookId);
      const repository = new CustomRunbookRepository(customRunbookTableName, documentClient);
      const v3 = await repository.findVersion(runbookId, 3);

      expect(v3?.deployedAccounts?.[ACCOUNT_A]).toMatchObject({ runbookVersion: 1, status: 'PENDING' });
    });

    it('rejects a rollback to a version that never passed testing', async () => {
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await harness.recordTest(runbookId, 1, V1_YAML);
      await harness.deploy(runbookId);

      // v2 is registered and tested; v1 is deliberately left with its passing
      // record so only the *named* version's own gate result can explain a reject.
      await harness.register(V2_YAML, runbookId);
      await harness.recordTest(runbookId, 2, V2_YAML, { testStatus: 'FAILED' });

      await expect(harness.deploy(runbookId, 2)).rejects.toThrow(/recorded test status is FAILED/);
    });

    it('rejects a deploy naming a version that does not exist', async () => {
      const registered = await harness.register(V1_YAML);
      await harness.recordTest(registered.runbook_id, 1, V1_YAML);

      await expect(harness.deploy(registered.runbook_id, 99)).rejects.toThrow(/not found/);
    });

    it('keeps an account FAILED when register merges versions and a DEPLOYED entry ties on runbookVersion', async () => {
      // Regression: a FAILED account keeps the runbookVersion it still runs and is never cleared
      // from other version maps, so a DEPLOYED entry on v1 and a FAILED entry on v2 can both carry
      // runbookVersion=1. Register's merge must not let the DEPLOYED entry win the tie and drop the
      // FAILED status — the failure has to stay visible on the newly staged version. Seed the two
      // records directly against DynamoDB Local, then register and read back the staged version.
      const repository = new CustomRunbookRepository(customRunbookTableName, documentClient);
      const registered = await harness.register(V1_YAML);
      const runbookId = registered.runbook_id;
      await repository.recordMemberDeployment(runbookId, 1, ACCOUNT_A, {
        runbookVersion: 1,
        ssmDocumentVersion: '1',
        status: 'DEPLOYED',
        attemptedAt: NOW,
      });
      await harness.register(V2_YAML, runbookId);
      await repository.recordMemberDeployment(runbookId, 2, ACCOUNT_A, {
        runbookVersion: 1,
        ssmDocumentVersion: '1',
        status: 'FAILED',
        attemptedAt: NOW,
        error: 'AccessDenied',
      });

      await harness.register(V1_YAML, runbookId);
      const v3 = await repository.findVersion(runbookId, 3);

      expect(v3?.deployedAccounts?.[ACCOUNT_A]).toMatchObject({ status: 'FAILED', error: 'AccessDenied' });
    });
  });
});
