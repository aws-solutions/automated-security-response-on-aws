// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { createHash } from 'node:crypto';
import {
  CreateDocumentCommand,
  DescribeDocumentCommand,
  DocumentAlreadyExists,
  DuplicateDocumentContent,
  SSMClient,
  UpdateDocumentCommand,
  UpdateDocumentDefaultVersionCommand,
} from '@aws-sdk/client-ssm';
import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import {
  DeployRunbookActionParams,
  DeployRunbookParams,
  DeployRunbookResult,
  MemberDeploymentState,
  RegisterRunbookParams,
  RunbookId,
  RunbookMetadata,
  SECURITY_CONTROL_STANDARD_NAME,
  SECURITY_CONTROL_STANDARD_VERSION,
} from '@asr/data-models';
import {
  CustomRunbookRepository,
  RunbookVersionConflictError,
} from '../../common/repositories/customRunbookRepository';
import { ControlsRepository } from '../../common/repositories/controlsRepository';
import { CrossAccountRoleService, validateIamActions } from './crossAccountRoleService';
import { MemberRunbookDocumentService } from './memberRunbookDocumentService';
import { Clock, getClock } from '../../common/utils/clock';
import { IdGenerator, getIdGenerator } from '../../common/utils/idGenerator';
import { createDynamoDBClient } from '../../common/utils/dynamodb';
import { BadRequestError, ConflictError, HttpError } from '../../common/utils/httpErrors';
import { apiLambdaEnvironment, assertCustomRunbooksConfigured } from '../apiLambdaEnvironment';

/**
 * Manages Custom Runbook lifecycle:
 * - register: stores runbook YAML in S3/DynamoDB as DRAFT
 * - deploy: transitions DRAFT → DEPLOYED, creates all SSM entries
 */
export class RunbookDeploymentService {
  private repository: CustomRunbookRepository | undefined;
  private controlsRepository: ControlsRepository | undefined;
  private ssmClient: SSMClient | undefined;
  private s3Client: S3Client | undefined;

  constructor(
    private readonly logger: Logger,
    private readonly clock: Clock = getClock(),
    private readonly idGenerator: IdGenerator = getIdGenerator(),
    private crossAccountRoleService?: CrossAccountRoleService,
    private memberRunbookDocumentService?: MemberRunbookDocumentService,
  ) {}

  private getRepository(): CustomRunbookRepository {
    this.repository ??= new CustomRunbookRepository(
      assertCustomRunbooksConfigured().tableName,
      createDynamoDBClient({ maxAttempts: 10 }),
    );
    return this.repository;
  }

  private getControlsRepository(): ControlsRepository {
    this.controlsRepository ??= new ControlsRepository(
      apiLambdaEnvironment().REMEDIATION_CONFIG_TABLE_NAME,
      createDynamoDBClient({ maxAttempts: 10 }),
    );
    return this.controlsRepository;
  }

  private getSsmClient(): SSMClient {
    this.ssmClient ??= new SSMClient({ maxAttempts: 3 });
    return this.ssmClient;
  }

  private getS3Client(): S3Client {
    this.s3Client ??= new S3Client({ maxAttempts: 3 });
    return this.s3Client;
  }

  /**
   * Best-effort delete of a single S3 object. Used only as a compensating action
   * when a register partially failed, so a delete failure here is logged and
   * swallowed — the caller is already unwinding and rethrows the original error.
   */
  private async deleteObjectQuietly(bucketName: string, key: string): Promise<void> {
    try {
      await this.getS3Client().send(new DeleteObjectCommand({ Bucket: bucketName, Key: key }));
    } catch (error) {
      this.logger.error('Failed to clean up orphaned S3 object after register rollback', {
        bucketName,
        key,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private getCrossAccountRoleService(): CrossAccountRoleService {
    this.crossAccountRoleService ??= new CrossAccountRoleService(this.logger);
    return this.crossAccountRoleService;
  }

  private getMemberRunbookDocumentService(): MemberRunbookDocumentService {
    this.memberRunbookDocumentService ??= new MemberRunbookDocumentService(this.logger);
    return this.memberRunbookDocumentService;
  }

  /**
   * @param actor authenticated principal (email) recorded as createdBy/deployedBy
   *   and carried into member-account RoleSessionNames for CloudTrail attribution.
   */
  async execute(params: DeployRunbookParams, actor?: string): Promise<DeployRunbookResult> {
    return params.action === 'register' ? this.handleRegister(params, actor) : this.handleDeploy(params, actor);
  }

  private async handleRegister(params: RegisterRunbookParams, actor?: string): Promise<DeployRunbookResult> {
    const { runbook_yaml, control_id, python_script } = params;
    const { bucketName } = assertCustomRunbooksConfigured();

    // runbookId is STABLE across versions (per design). Registering against an
    // existing runbook_id adds a new version to it; omitting it starts a new
    // runbook at v1. Version is scoped to the runbookId — not the whole control.
    const runbookId: RunbookId = params.runbook_id ? params.runbook_id : (this.idGenerator.randomUUID() as RunbookId);

    // Conditional-create retry loop: compute the next version from this
    // runbook's own latest, then atomically create that (runbookId, version)
    // slot. If a concurrent register took the same slot, recompute and retry —
    // this closes the version race (no silent last-writer-wins). Exhausting the
    // retries falls through to the ConflictError after the loop.
    // S3 writes happen AFTER the conditional create succeeds so a losing
    // concurrent register never overwrites the winner's YAML.
    const MAX_ATTEMPTS = 5;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const metadata = await this.claimVersionSlot(runbookId, params, actor, attempt);
      // Slot taken by a concurrent register — recompute the version and retry.
      if (!metadata) continue;

      await this.uploadRegisterContent(bucketName, metadata, runbook_yaml, python_script);

      this.logger.info('Registered Custom Runbook', {
        runbookId,
        controlId: control_id,
        version: metadata.version,
      });
      return {
        action: 'register',
        runbook_id: runbookId,
        version: metadata.version,
        status: 'DRAFT',
        control_id,
        s3_key: metadata.s3Key,
      };
    }

    throw new ConflictError(`Failed to register a new version after ${MAX_ATTEMPTS} attempts (version contention)`);
  }

  /**
   * Atomically claims the next (runbookId, version) slot for a register and
   * returns the metadata that was written, or `undefined` when a concurrent
   * register won that slot and the caller should recompute and retry.
   *
   * @param attempt current retry attempt, logged to make contention visible.
   * @throws ConflictError if `runbookId` is already bound to a different control.
   */
  private async claimVersionSlot(
    runbookId: RunbookId,
    params: RegisterRunbookParams,
    actor: string | undefined,
    attempt: number,
  ): Promise<RunbookMetadata | undefined> {
    const { control_id, python_script, service_name, description, runbook_yaml } = params;
    // Read every version, not just the numerically-latest one: a rollback empties the
    // higher-numbered records' account maps, so the fleet's current state has to be merged
    // across all versions (see stageAccountsForNewVersion). `latest` is still the highest
    // version — used for the version bump and the one-control-per-runbookId invariant.
    const allVersions = await this.getRepository().findAllVersions(runbookId);
    const latest = allVersions.reduce<RunbookMetadata | undefined>(
      (highest, record) => (highest === undefined || record.version > highest.version ? record : highest),
      undefined,
    );

    // A runbookId is bound to one control (the controlId-status GSI assumes
    // one runbookId → one control). Reject reusing an existing id under a
    // different control rather than corrupting that mapping.
    if (latest && latest.controlId !== control_id) {
      throw new ConflictError(
        `Runbook ${runbookId} is registered under control ${latest.controlId}, not ${control_id}`,
      );
    }

    const version = latest ? latest.version + 1 : 1;
    const metadata: RunbookMetadata = {
      runbookId,
      version,
      controlId: control_id,
      serviceName: service_name ?? control_id.split('.')[0],
      description: description ?? `Custom remediation for ${control_id}`,
      remediationAction: `Custom remediation for ${control_id}`,
      status: 'DRAFT',
      s3Key: `runbooks/${runbookId}/v${version}/runbook.yaml`,
      scriptS3Key: python_script ? `runbooks/${runbookId}/v${version}/script.py` : undefined,
      // Bind the registered content to this version at register time. test_runbook_yaml
      // hashes the YAML it runs the same way (sha256 over utf8) and records a pass only
      // when it matches, and deploy compares testedContentDigest against this. Omitting
      // it made every registered version look like a pre-digest legacy record, so the
      // recorded-test path rejected it and no version could ever be deployed.
      registeredContentDigest: createHash('sha256').update(runbook_yaml, 'utf8').digest('hex'),
      createdBy: actor ?? 'mcp-deploy',
      createdAt: this.clock.now().toISOString(),
      deployedAccounts: stageAccountsForNewVersion(allVersions),
    };

    try {
      await this.getRepository().createVersion(metadata);
    } catch (error) {
      // A lost version race retries with a recomputed version; the loop bound
      // in the caller is what limits attempts, so no per-attempt guard here.
      if (error instanceof RunbookVersionConflictError) {
        this.logger.warn('Version slot taken by a concurrent register — retrying', {
          runbookId,
          version,
          attempt,
        });
        return undefined;
      }
      throw error;
    }

    return metadata;
  }

  /**
   * Writes the runbook YAML (and optional python script) for a claimed version.
   *
   * On any S3 failure this compensates by deleting the objects that did land and
   * the DynamoDB record claimed by `claimVersionSlot`, so a partial register
   * leaves neither an orphaned metadata entry nor an orphaned object, then
   * rethrows the original S3 error.
   */
  private async uploadRegisterContent(
    bucketName: string,
    metadata: RunbookMetadata,
    runbookYaml: string,
    pythonScript?: string,
  ): Promise<void> {
    const { runbookId, version, s3Key, scriptS3Key } = metadata;

    try {
      await this.getS3Client().send(
        new PutObjectCommand({
          Bucket: bucketName,
          Key: s3Key,
          Body: runbookYaml,
          ContentType: 'application/x-yaml',
        }),
      );

      if (pythonScript && scriptS3Key) {
        await this.getS3Client().send(
          new PutObjectCommand({
            Bucket: bucketName,
            Key: scriptS3Key,
            Body: pythonScript,
            ContentType: 'text/x-python',
          }),
        );
      }
    } catch (s3Error) {
      // The YAML upload can succeed and the script upload then fail, so both
      // keys are cleaned up.
      this.logger.error('S3 upload failed after DynamoDB write — rolling back metadata and objects', {
        runbookId,
        version,
        error: s3Error instanceof Error ? s3Error.message : String(s3Error),
      });
      await this.deleteObjectQuietly(bucketName, s3Key);
      if (scriptS3Key) {
        await this.deleteObjectQuietly(bucketName, scriptS3Key);
      }
      await this.deleteVersionQuietly(runbookId, version);
      throw s3Error;
    }
  }

  /**
   * Best-effort delete of a claimed version record. Used only as a compensating
   * action while unwinding a partially failed register, so a delete failure is
   * logged and swallowed — the caller rethrows the original error.
   */
  private async deleteVersionQuietly(runbookId: RunbookId, version: number): Promise<void> {
    try {
      await this.getRepository().deleteVersion(runbookId, version);
    } catch (deleteError) {
      this.logger.error('Failed to roll back DynamoDB metadata after S3 failure', {
        runbookId,
        version,
        error: deleteError instanceof Error ? deleteError.message : String(deleteError),
      });
    }
  }

  private async handleDeploy(params: DeployRunbookActionParams, actor?: string): Promise<DeployRunbookResult> {
    const { runbook_id, control_id } = params;

    // Resolve the exact version to release and run every pre-side-effect guard before any
    // SSM/IAM/status change (see resolveDeployTarget).
    const { metadata, releaseAccountIds, requestedIamActions } = await this.resolveDeployTarget(params);

    // Managed Custom Runbooks fill gaps only. Resolve the same per-control remap
    // the Orchestrator uses, then describe the effective built-in document in
    // every requested account. Any existing built-in rejects the whole release.
    // An account whose read-only preflight fails is excluded from this release,
    // because treating an unknown result as "no built-in" could install a custom
    // document over a control the solution already owns.
    const memberDocumentService = this.getMemberRunbookDocumentService();
    const remediationControlId = await memberDocumentService.resolveRemediationControlId(
      this.getSsmClient(),
      control_id,
    );
    const memberPreflight = await memberDocumentService.prepareDeploymentTargets(
      releaseAccountIds,
      control_id,
      remediationControlId,
      actor,
    );
    if (memberPreflight.collisions.length > 0) {
      this.logger.warn('Refusing to deploy a Custom Runbook over a built-in remediation', {
        runbookId: runbook_id,
        version: metadata.version,
        controlId: control_id,
        collisions: memberPreflight.collisions,
      });
      throw new BadRequestError(
        `Cannot create a custom runbook for ${control_id}: ASR already provides a built-in remediation for ` +
          'this control (directly or through a control remap) in at least one requested member account, so a ' +
          'custom runbook cannot be created or deployed for it. Built-in remediations always take precedence at ' +
          'runtime; Managed Custom Runbooks can only fill controls that have no built-in runbook.',
      );
    }

    if (memberPreflight.ready.length === 0) {
      this.logger.error('Built-in runbook preflight failed in every requested member account', {
        runbookId: runbook_id,
        version: metadata.version,
        requestedAccounts: releaseAccountIds.length,
        failures: memberPreflight.failed,
      });
      throw new HttpError(
        502,
        `Deploy failed: ASR could not verify built-in runbook coverage in any of the ` +
          `${releaseAccountIds.length} requested member account(s). No runbook resources were changed; ` +
          'retry after member-account access is restored.',
      );
    }

    if (metadata.status === 'DEPLOYED') {
      this.logger.info('Re-deploying already deployed runbook', {
        runbook_id,
        controlId: control_id,
      });
    }

    const yamlContent = await this.fetchVerifiedRunbookContent(metadata);

    // Custom runbooks always use ASR-Custom-SC_{version}_{control}. The standard and version
    // are fixed constants, not caller input: a wrong value would install under a name the
    // runtime resolver never looks up, and would also have made the collision preflight above
    // probe the wrong built-in document.
    const documentName = `ASR-Custom-${SECURITY_CONTROL_STANDARD_NAME}_${SECURITY_CONTROL_STANDARD_VERSION}_${control_id}`;

    const documentVersion = await this.createOrPromoteAdminDocument(documentName, yamlContent);

    // Discovery is driven entirely by the CustomRunbookTable (the Orchestrator
    // queries it by controlId for a DEPLOYED record). The previous
    // /Solutions/SO0111/CustomRunbook/{control} and /Custom/{control}/status SSM
    // parameters were write-only — never read by the resolver — so they are not
    // written. DynamoDB is the single source of truth for discovery + status.

    const remediationRole = `SO0111-Remediate-Custom-${SECURITY_CONTROL_STANDARD_NAME}-${SECURITY_CONTROL_STANDARD_VERSION}-${control_id}`;

    // The execution role has to exist before the document lands, otherwise a
    // finding arriving in between resolves a document it cannot assume a role for.
    // Only preflight-ready accounts are eligible: a failed built-in check must
    // never fall through to a write.
    const preflightReadyAccountIds = memberPreflight.ready.map((target) => target.accountId);
    const roleProvisioning = await this.getCrossAccountRoleService().provisionRolesInAccounts(
      preflightReadyAccountIds,
      remediationRole,
      requestedIamActions,
      documentName,
      control_id,
      actor,
    );
    this.logger.info('Role provisioning complete', {
      succeeded: roleProvisioning.succeeded.length,
      failed: roleProvisioning.failed.length,
    });

    // Skip accounts whose role provisioning failed — installing a document there
    // would report a successful release the account cannot execute.
    const failedRoleAccountIds = new Set(roleProvisioning.failed.map((failure) => failure.accountId));
    const documentTargets = memberPreflight.ready.filter((target) => !failedRoleAccountIds.has(target.accountId));

    const result = await memberDocumentService.deployToPreparedAccounts(
      documentTargets,
      documentName,
      yamlContent,
      control_id,
      actor,
    );

    const failures = [
      ...memberPreflight.failed.map((failure) => ({
        accountId: failure.accountId,
        error: `Built-in runbook preflight failed: ${failure.error}`,
      })),
      ...result.failed,
      ...roleProvisioning.failed.map((failure) => ({
        accountId: failure.accountId,
        error: `Remediation role provisioning failed: ${failure.error}`,
      })),
    ];
    const documentDeployment: DeployRunbookResult['document_deployment'] = {
      succeeded: result.succeeded.map((account) => account.accountId),
      failed: failures,
    };

    const releasedStates = this.buildMemberStates(metadata, result.succeeded, failures, documentVersion);
    await this.persistMemberDeployments(runbook_id, metadata.version, releasedStates, result.succeeded);
    this.logger.info('Member-account document release complete', {
      succeeded: result.succeeded.length,
      failed: failures.length,
    });

    // A deploy that named member accounts but installed the runbook in none of
    // them cannot execute anywhere. Marking the version DEPLOYED here would
    // publish it as live (controlsService advertises DEPLOYED records and the
    // Orchestrator resolves them by controlId), so fail loudly instead — the
    // per-account states are already recorded above for diagnosis.
    if (documentDeployment.succeeded.length === 0) {
      // Full per-account detail (account IDs + raw SDK errors) stays in the
      // logs and the recorded member states; the response body must not
      // disclose member account IDs or backend error internals.
      this.logger.error('Deploy installed the runbook in no member accounts', {
        runbookId: runbook_id,
        version: metadata.version,
        requestedAccounts: releaseAccountIds.length,
        failures: documentDeployment.failed,
      });
      throw new HttpError(
        502,
        `Deploy failed: the runbook was installed in none of the ${releaseAccountIds.length} requested member ` +
          'account(s). Per-account failures are recorded in the runbook deployment state and service logs.',
      );
    }

    const deployedAt = this.clock.now().toISOString();
    const deployedBy = actor ?? 'mcp-deploy';
    await this.getRepository().updateStatus(runbook_id, metadata.version, 'DEPLOYED', {
      ssmDocumentName: documentName,
      ssmDocumentVersion: documentVersion,
      remediationRole: remediationRole,
      deployedBy,
      deployedAt,
    });

    await this.createCustomControlEntry(control_id, metadata, deployedBy, deployedAt);

    this.logger.info('Deployed Custom Runbook', {
      documentName,
      controlId: control_id,
    });
    return {
      action: 'deploy',
      runbook_id: runbook_id,
      version: metadata.version,
      status: 'DEPLOYED',
      control_id,
      document_name: documentName,
      document_version: documentVersion,
      remediation_role: remediationRole,
      role_provisioning: roleProvisioning,
      document_deployment: documentDeployment,
      version_consistency: summarizeVersionConsistency(metadata.version, {
        ...metadata.deployedAccounts,
        ...releasedStates,
      }),
    };
  }

  /**
   * Resolve the version a deploy targets and run the pre-side-effect guards (each explained
   * inline). Returns the version metadata, the accounts to release to, and the validated IAM actions.
   */
  private async resolveDeployTarget(
    params: DeployRunbookActionParams,
  ): Promise<{ metadata: RunbookMetadata; releaseAccountIds: string[]; requestedIamActions: string[] }> {
    const { runbook_id, control_id } = params;

    // A caller naming `version` is releasing that exact version — the documented
    // rollback mechanism (deploy_runbook(deploy, runbook_id, version=N) repoints
    // the document at that version's stored YAML). Resolving the latest instead
    // would redeploy the newest version, which during a rollback is the very
    // version being rolled back.
    const metadata =
      params.version === undefined
        ? await this.getRepository().findLatestVersion(runbook_id)
        : await this.getRepository().findVersion(runbook_id, params.version);
    if (!metadata) {
      throw new BadRequestError(
        params.version === undefined
          ? `Custom Runbook not found: ${runbook_id}`
          : `Custom Runbook not found: ${runbook_id} version ${params.version}`,
      );
    }

    // The runbookId is permanently bound to the control used at register time.
    // Besides preventing inconsistent metadata, this closes the built-in
    // collision guard against a caller checking one control_id and releasing a
    // runbook registered for another.
    if (metadata.controlId !== control_id) {
      throw new BadRequestError(
        `Runbook ${runbook_id} is registered under control ${metadata.controlId}, not ${control_id}`,
      );
    }

    // Only the accounts named here are released to. Everything else keeps the
    // version it already runs and remains pending.
    const releaseAccountIds = params.member_account_ids ?? [];

    // A deploy releases the runbook copy-per-member: each named account gets its
    // own SSM document and scoped remediation role. Naming none creates no role or
    // document in any account, so it must not write a DEPLOYED record — which
    // controlsService.getAllControls publishes and the Orchestrator resolves by
    // controlId — whose executions would only die at AssumeRole. Reject here,
    // before the admin-account document create and the status write. (The schema
    // also enforces this; this guard covers direct service callers.)
    if (releaseAccountIds.length === 0) {
      throw new BadRequestError(
        'member_account_ids must name at least one account: a deploy releases the runbook to member ' +
          'accounts, and one that targets none cannot produce a working remediation. Use register to ' +
          'stage a version without releasing it.',
      );
    }

    // A member release without required_iam_actions would install the SSM document
    // but leave no remediation role for it to assume — executions would fail on
    // AssumeRole. Require the actions up front so this misconfiguration surfaces
    // at deploy time, not at the first finding. (releaseAccountIds is non-empty
    // here — the zero-account guard above already returned.)
    if (!params.required_iam_actions || params.required_iam_actions.length === 0) {
      throw new BadRequestError(
        'required_iam_actions must be provided when deploying to member accounts. ' +
          'The remediation role needs at least the actions the runbook calls.',
      );
    }

    // Validate IAM action format and forbidden namespaces early — before any
    // SSM, IAM, or status changes — so a malformed request fails fast. The guard
    // above narrows required_iam_actions to a non-empty array here.
    const requestedIamActions = params.required_iam_actions;
    validateIamActions(requestedIamActions);

    // Enforce the test-before-deploy gate. CR3 records a version's outcome via
    // test_runbook_yaml (testStatus, testedContentDigest bound to the registered
    // YAML, and the exact testedIamActions its bounded test role was granted).
    // Deploy is the only place that gate is enforced, so without this an
    // untested, FAILED, or differently-permissioned version would install and
    // run in member accounts. Checked before any SSM/IAM side effect.
    this.assertVersionPassedTest(metadata, requestedIamActions);

    return { metadata, releaseAccountIds, requestedIamActions };
  }

  /**
   * Fetch the registered YAML for a version from S3 and verify its bytes against the
   * registration digest before it is installed anywhere.
   */
  private async fetchVerifiedRunbookContent(metadata: RunbookMetadata): Promise<string> {
    const { bucketName } = assertCustomRunbooksConfigured();
    // A missing object (NoSuchKey) or bucket (NoSuchBucket) throws from send(); treat both the
    // same as an empty body — the metadata survived but its content did not — so the friendly
    // 500 below is reached instead of an uncaught error that could surface the bucket name.
    // Matched by error name rather than instanceof, following the repo pattern
    // (iacTemplateSyncHandler): SDK error classes do not reliably satisfy instanceof across
    // mock-constructed errors and SDK versions.
    let yamlContent: string | undefined;
    try {
      const response = await this.getS3Client().send(new GetObjectCommand({ Bucket: bucketName, Key: metadata.s3Key }));
      yamlContent = await response.Body?.transformToString();
    } catch (error) {
      const errorName = error instanceof Error ? error.name : '';
      if (errorName !== 'NoSuchKey' && errorName !== 'NoSuchBucket') throw error;
    }
    if (!yamlContent) {
      // The bucket and key identify backend storage, so they stay in the logs; the
      // response says only that the content is unavailable. Reaching here means the
      // metadata survived but its object did not, so re-registering is the way out.
      this.logger.error('Registered runbook version has no content in S3', {
        runbookId: metadata.runbookId,
        version: metadata.version,
        bucketName,
        s3Key: metadata.s3Key,
      });
      throw new HttpError(
        500,
        'Deploy failed: the stored content for this runbook version could not be read. ' +
          'Register the version again before deploying.',
      );
    }

    // The gate above compares two DynamoDB attributes to each other; the bytes
    // that actually install into member accounts come from S3, so without this
    // the one artifact that runs under an elevated remediation role is the one
    // input never checked against the digest chain. Re-hash what was fetched so
    // "the bytes about to deploy are the bytes that were proven" holds for the
    // object too, not just for the metadata describing it. Any divergence — a
    // write to the bucket that did not go through register, or a truncated
    // object — fails the deploy instead of silently installing untested code.
    this.assertStoredContentMatchesRegistration(metadata, yamlContent, bucketName);
    return yamlContent;
  }

  /** Returns the SSM document version to record for the release. */
  private async createOrPromoteAdminDocument(documentName: string, yamlContent: string): Promise<string> {
    let documentVersion: string;
    try {
      const res = await this.getSsmClient().send(
        new CreateDocumentCommand({
          Name: documentName,
          Content: yamlContent,
          DocumentType: 'Automation',
          DocumentFormat: 'YAML',
        }),
      );
      documentVersion = res.DocumentDescription?.DocumentVersion ?? '1';
    } catch (error) {
      if (error instanceof DocumentAlreadyExists) {
        documentVersion = await this.updateAdminDocument(documentName, yamlContent);
      } else throw error;
    }

    // UpdateDocument creates a new document version but leaves the previous one
    // as default, and an unqualified StartAutomationExecution runs the default.
    // Without this promotion a re-deployed runbook would be installed but never
    // actually executed.
    await this.getSsmClient().send(
      new UpdateDocumentDefaultVersionCommand({
        Name: documentName,
        DocumentVersion: documentVersion,
      }),
    );
    return documentVersion;
  }

  /**
   * Record each released account's state on the version just deployed, then clear those
   * accounts from every other version's map so each account appears under exactly the version
   * it now runs. The clear is best-effort: a failure degrades to a stale cross-version count,
   * not a failed deploy.
   */
  private async persistMemberDeployments(
    runbookId: RunbookId,
    version: number,
    releasedStates: Record<string, MemberDeploymentState>,
    succeededAccounts: readonly { accountId: string }[],
  ): Promise<void> {
    for (const [accountId, state] of Object.entries(releasedStates)) {
      await this.getRepository().recordMemberDeployment(runbookId, version, accountId, state);
    }

    for (const account of succeededAccounts) {
      try {
        await this.getRepository().clearAccountFromOtherVersions(runbookId, version, account.accountId);
      } catch (error) {
        this.logger.warn('Could not clear a released account from other runbook versions', {
          runbookId,
          keepVersion: version,
          accountId: account.accountId,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  /**
   * Write the convenience Controls entry that surfaces a deployed custom control in
   * listControls. Secondary to the DEPLOYED status already set, so a failure here is logged and
   * swallowed rather than failing an otherwise-successful deploy; the write is idempotent, so a
   * later deploy fills it in.
   */
  private async createCustomControlEntry(
    controlId: string,
    metadata: RunbookMetadata,
    deployedBy: string,
    deployedAt: string,
  ): Promise<void> {
    try {
      await this.getControlsRepository().createCustomControlIfAbsent({
        controlId,
        description: metadata.description || `Custom runbook for ${controlId}`,
        modifiedBy: deployedBy,
        lastModified: deployedAt,
      });
    } catch (error) {
      this.logger.error(
        'Runbook deployed, but writing its Controls entry failed — the control will not surface in ' +
          'listControls until a later deploy recreates it. The deploy itself is unaffected.',
        {
          controlId,
          runbookId: metadata.runbookId,
          version: metadata.version,
          error: error instanceof Error ? error.message : String(error),
        },
      );
    }
  }

  /**
   * Refuse to deploy a version that has not passed a content-and-permission-bound
   * test. Enforces three things recorded by test_runbook_yaml (see
   * CustomRunbookTestResultRepository):
   *
   *  1. testStatus is PASSED — an untested (undefined) or FAILED version is rejected.
   *  2. The YAML that was tested is the YAML registered for this version
   *     (testedContentDigest === registeredContentDigest), so the bytes about to
   *     deploy are the bytes that were proven. A digest recorded before the last
   *     re-register would not match.
   *  3. The exact IAM action set the test role was granted (testedIamActions)
   *     equals the set being requested now. A version proven with one permission
   *     set must not deploy with a wider or different one, or the remediation runs
   *     with permissions its test never exercised.
   *
   * `testAccountId` is intentionally NOT matched against any configured account:
   * the recording side stamps it for provenance only, so the runbook is proven
   * wherever the MCP server ran it. All checks run before any SSM/IAM side effect.
   */
  private assertVersionPassedTest(metadata: RunbookMetadata, requestedIamActions: readonly string[]): void {
    if (metadata.testStatus !== 'PASSED') {
      throw new BadRequestError(
        `Custom Runbook version ${metadata.version} cannot be deployed: its recorded test status is ` +
          `${metadata.testStatus ?? 'untested'}. Run test_runbook_yaml against this version and record a ` +
          'PASSED result before deploying.',
      );
    }

    if (!metadata.testedContentDigest || metadata.testedContentDigest !== metadata.registeredContentDigest) {
      throw new BadRequestError(
        `Custom Runbook version ${metadata.version} cannot be deployed: the content that passed testing is ` +
          'not the content currently registered for this version. Re-test the registered YAML before deploying.',
      );
    }

    const testedActions = new Set(metadata.testedIamActions ?? []);
    const requestedActions = new Set(requestedIamActions);
    const setsMatch =
      testedActions.size === requestedActions.size &&
      [...requestedActions].every((action) => testedActions.has(action));
    if (!setsMatch) {
      throw new BadRequestError(
        `Custom Runbook version ${metadata.version} cannot be deployed: the requested IAM actions do not match ` +
          'the actions its test role was granted. Re-test the version with the exact required_iam_actions you ' +
          'intend to deploy, so it is proven with the same permissions.',
      );
    }
  }

  /**
   * Refuse to install a stored artifact whose bytes are not the bytes registered
   * for this version.
   *
   * `assertVersionPassedTest` proves the *metadata* is consistent — the digest
   * recorded by the test equals the digest recorded by the register. Neither
   * digest is derived from the object that a deploy actually reads, so this
   * closes the chain by hashing the fetched YAML the same way both other hops do
   * (sha256 over utf8) and comparing it to the registration.
   *
   * A legacy version carrying no `registeredContentDigest` cannot be verified and
   * is rejected rather than trusted: the test gate already refuses such a version,
   * so reaching here with one means the two checks disagree.
   */
  private assertStoredContentMatchesRegistration(
    metadata: RunbookMetadata,
    yamlContent: string,
    bucketName: string,
  ): void {
    const storedContentDigest = createHash('sha256').update(yamlContent, 'utf8').digest('hex');
    if (metadata.registeredContentDigest === storedContentDigest) return;

    // The digests themselves are not disclosed to the caller; they are recorded
    // here so an operator can tell tampering from truncation.
    this.logger.error('Stored runbook artifact does not match its registered content digest — refusing to deploy', {
      runbookId: metadata.runbookId,
      version: metadata.version,
      s3Key: metadata.s3Key,
      bucketName,
      registeredContentDigest: metadata.registeredContentDigest,
      storedContentDigest,
    });
    throw new BadRequestError(
      `Custom Runbook version ${metadata.version} cannot be deployed: its stored runbook content does not ` +
        'match the content registered and tested for this version. Re-register the intended YAML as a new ' +
        'version and test it before deploying.',
    );
  }

  /**
   * Update an already-existing admin-account document to the new content and
   * return the version to promote. Re-deploying byte-identical YAML — splitting a
   * rollout across several deploy calls (as the schema comment recommends) or
   * retrying a failed deploy — makes SSM reject the update with
   * `DuplicateDocumentContent`. That is not an error here: the content is already
   * the current `$LATEST`, so resolve its version and let the default-version
   * promotion run. Mirrors MemberRunbookDocumentService/DriftDetectionService.
   */
  private async updateAdminDocument(documentName: string, yamlContent: string): Promise<string> {
    try {
      const res = await this.getSsmClient().send(
        new UpdateDocumentCommand({
          Name: documentName,
          Content: yamlContent,
          DocumentVersion: '$LATEST',
          DocumentFormat: 'YAML',
        }),
      );
      return res.DocumentDescription?.DocumentVersion ?? '1';
    } catch (error) {
      if (!(error instanceof DuplicateDocumentContent)) throw error;
      const described = await this.getSsmClient().send(
        new DescribeDocumentCommand({ Name: documentName, DocumentVersion: '$LATEST' }),
      );
      return described.Document?.DocumentVersion ?? '1';
    }
  }

  /** Build the per-account state records for one release attempt. */
  private buildMemberStates(
    metadata: RunbookMetadata,
    succeeded: Array<{ accountId: string; ssmDocumentVersion: string }>,
    failed: Array<{ accountId: string; error: string }>,
    adminDocumentVersion?: string,
  ): Record<string, MemberDeploymentState> {
    const attemptedAt = this.clock.now().toISOString();
    const states: Record<string, MemberDeploymentState> = {};

    for (const account of succeeded) {
      states[account.accountId] = {
        runbookVersion: metadata.version,
        ssmDocumentVersion: account.ssmDocumentVersion,
        status: 'DEPLOYED',
        attemptedAt,
      };
    }

    for (const failure of failed) {
      // A failed account keeps the version it was last known to run, so the
      // release backlog still shows what is actually installed there.
      const previous = metadata.deployedAccounts?.[failure.accountId];
      states[failure.accountId] = {
        runbookVersion: previous?.runbookVersion ?? metadata.version,
        ssmDocumentVersion: previous?.ssmDocumentVersion ?? adminDocumentVersion ?? '1',
        status: 'FAILED',
        attemptedAt,
        error: failure.error,
      };
    }

    return states;
  }
}

/**
 * Carry a runbook's member accounts onto a newly registered version as PENDING.
 *
 * Registering a new version must not change what any member account runs, so every account
 * that already had this runbook is staged for release rather than updated. Accounts whose
 * last release failed keep FAILED so the failure stays visible across versions instead of
 * being reset to a clean pending state.
 *
 * The fleet's current state is merged across ALL existing version records, not read from the
 * single numerically-latest one. `clearAccountFromOtherVersions` removes an account from
 * every version except the one it runs, so after a rollback (deploying an older version) the
 * highest-numbered record's map is empty while the fleet actually runs an older version.
 * Reading only that record would stage the new version with zero accounts and silently drop
 * the fleet. Merging takes each account from whichever version most recently ran it (its
 * `runbookVersion`), which reconstructs the true fleet regardless of which record holds it.
 */
function stageAccountsForNewVersion(
  allVersions: readonly RunbookMetadata[],
): Record<string, MemberDeploymentState> | undefined {
  // For each account, keep the entry from the version it most recently ran (highest
  // runbookVersion). Records can legitimately duplicate an account across versions: a FAILED
  // account keeps the runbookVersion it still runs and is never cleared from other versions,
  // so a DEPLOYED entry and a FAILED entry can tie on runbookVersion. On a tie, prefer the
  // FAILED entry so the failure stays visible across versions — the invariant this staging
  // documents — rather than letting iteration order silently drop it.
  const currentByAccount = new Map<string, MemberDeploymentState>();
  for (const record of allVersions) {
    for (const [accountId, state] of Object.entries(record.deployedAccounts ?? {})) {
      const existing = currentByAccount.get(accountId);
      if (!existing) {
        currentByAccount.set(accountId, state);
        continue;
      }
      if (
        state.runbookVersion > existing.runbookVersion ||
        (state.runbookVersion === existing.runbookVersion && state.status === 'FAILED')
      ) {
        currentByAccount.set(accountId, state);
      }
    }
  }
  if (currentByAccount.size === 0) return undefined;

  return Object.fromEntries(
    [...currentByAccount.entries()].map(([accountId, state]) => [
      accountId,
      state.status === 'FAILED' ? state : { ...state, status: 'PENDING' as const },
    ]),
  );
}

/**
 * Compare every known member account against the version just released.
 *
 * `consistent` is false while any account is still pending or failed, which is
 * the signal that the fleet is mid-rollout and the remaining accounts have to be
 * named in a follow-up deploy.
 */
function summarizeVersionConsistency(
  targetVersion: number,
  accounts: Record<string, MemberDeploymentState>,
): DeployRunbookResult['version_consistency'] {
  const accountsOnTarget: string[] = [];
  const accountsPendingRelease: Array<{ accountId: string; runbookVersion: number }> = [];
  const accountsFailed: string[] = [];

  for (const [accountId, state] of Object.entries(accounts)) {
    if (state.status === 'FAILED') accountsFailed.push(accountId);
    else if (state.status === 'DEPLOYED' && state.runbookVersion === targetVersion) accountsOnTarget.push(accountId);
    else accountsPendingRelease.push({ accountId, runbookVersion: state.runbookVersion });
  }

  return {
    consistent: accountsPendingRelease.length === 0 && accountsFailed.length === 0,
    target_version: targetVersion,
    accounts_on_target: accountsOnTarget,
    accounts_pending_release: accountsPendingRelease,
    accounts_failed: accountsFailed,
  };
}
