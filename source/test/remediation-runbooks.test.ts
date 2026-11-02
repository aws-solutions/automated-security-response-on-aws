// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { mkdtempSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { basename, join } from 'path';
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { compareVersions } from 'compare-versions';
import { getMemberStackLimit } from '../lib/config/cdk-config';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { RemediationRunbookStack } from '../lib/remediation-runbook-stack';
import {
  chunkRunbooks,
  RemediationRunbookEntry,
  REMEDIATION_RUNBOOK_DOCUMENTS,
  runbookStackCount,
  runbookStackSuffix,
} from '../lib/remediation-runbooks';

// The frozen source-order prefix of chunk 0. Any insert, delete, reorder, or rename that would move
// an already-shipped runbook across the chunk-0 boundary makes this literal stop matching and fails
// the build, which is exactly the append-only guarantee that keeps fixed ASR-<name> documents from
// colliding across nested stacks on an in-place upgrade.
const GOLDEN_CHUNK0_NAMES: readonly string[] = [
  'CreateCloudTrailMultiRegionTrail',
  'CreateLogMetricFilterAndAlarm',
  'EnableAutoScalingGroupELBHealthCheck',
  'EnableAWSConfig',
  'EnableCloudTrailToCloudWatchLogging',
  'EnableCloudTrailEncryption',
  'EnableDefaultEncryptionS3',
  'EnableCFNTerminationProtection',
  'EnableS3BucketVersioning',
  'EnableVPCFlowLogs',
  'CreateAccessLoggingBucket',
  'MakeEBSSnapshotsPrivate',
  'MakeRDSSnapshotPrivate',
  'RemoveLambdaPublicAccess',
  'RevokeUnrotatedKeys',
  'SetSSLBucketPolicy',
  'ReplaceCodeBuildClearTextCredentials',
  'S3BlockDenylist',
  'EncryptRDSSnapshot',
  'DisablePublicAccessToRedshiftCluster',
  'EnableRedshiftClusterAuditLogging',
  'EnableAutomaticVersionUpgradeOnRedshiftCluster',
  'EnableAutomaticSnapshotsOnRedshiftCluster',
  'CreateIAMSupportRole',
  'EnableEncryptionForSQSQueue',
  'ConfigureSNSTopicForStack',
  'ConfigureS3BucketPublicAccessBlock',
  'ConfigureS3PublicAccessBlock',
  'EnableCloudTrailLogFileValidation',
  'EnableEbsEncryptionByDefault',
  'EnableEnhancedMonitoringOnRDSInstance',
  'EnableKeyRotation',
  'EnableRDSClusterDeletionProtection',
  'EnableCopyTagsToSnapshotOnRDSCluster',
  'EnableRDSInstanceDeletionProtection',
  'EnableMultiAZOnRDSInstance',
  'RemoveVPCDefaultSecurityGroupRules',
  'RevokeUnusedIAMUserCredentials',
  'SetIAMPasswordPolicy',
  'DisablePublicAccessToRDSInstance',
  'EnableMinorVersionUpgradeOnRDSDBInstance',
  'EnableEncryptionForSNSTopic',
  'EnableDeliveryStatusLoggingForSNSTopic',
  'DisablePublicIPAutoAssign',
  'EnableIMDSV2OnInstance',
  'RemoveCodeBuildPrivilegedMode',
  'EnableCloudFrontDefaultRootObject',
  'BlockSSMDocumentPublicAccess',
  'EnableSSMDocumentBlockPublicSharing',
  'AttachSSMPermissionsToEC2',
  'AttachServiceVPCEndpoint',
  'EnableBucketEventNotifications',
  'ConfigureDynamoDBAutoScaling',
  'EnableDynamoDBDeletionProtection',
  'EnableElastiCacheBackups',
  'EnforceHTTPSForALB',
  'LimitECSRootFilesystemAccess',
  'EnableElastiCacheReplicationGroupFailover',
  'EnableElastiCacheVersionUpgrades',
  'SetCloudFrontOriginDomain',
  'DisableUnrestrictedAccessToHighRiskPorts',
  'EnablePrivateRepositoryScanning',
  'SetS3LifecyclePolicy',
  'UpdateSecretRotationPeriod',
  'DisableTGWAutoAcceptSharedAttachments',
  'EnableGuardDuty',
  'TagDynamoDBTableResource',
  'TagGuardDutyResource',
  'EnableAutoSecretRotation',
  'RevokeUnauthorizedInboundRules',
  'RemoveUnusedSecret',
  'SetLogGroupRetentionDays',
  'EnableAPIGatewayCacheDataEncryption',
  'ConfigureAutoScalingLaunchConfigToRequireIMDSv2',
  'ConfigureAutoScalingLaunchConfigNoPublicIP',
  'EnableMacie',
  'EnableAPIGatewayExecutionLogs',
  'EnableAthenaWorkGroupLogging',
  'TightenResourcePolicy',
];

describe('memberStackLimits runbook config', () => {
  test('getMemberStackLimit("runbook") resolves to 79, not the Infinity fallback', () => {
    const limit = getMemberStackLimit('runbook');
    expect(limit).toBe(79);
    expect(Number.isFinite(limit)).toBe(true);
  });
});

describe('REMEDIATION_RUNBOOK_DOCUMENTS metadata', () => {
  test('has exactly 79 entries', () => {
    expect(REMEDIATION_RUNBOOK_DOCUMENTS).toHaveLength(79);
  });

  test('all names are unique', () => {
    const names = REMEDIATION_RUNBOOK_DOCUMENTS.map((entry) => entry.name);
    expect(new Set(names).size).toBe(names.length);
  });

  // Validity only: every versionAdded must parse as semver and be a real release (> 0.0.0). The
  // append-only ordering (new entries outrank the frozen prefix) is enforced by the dedicated
  // "append-only guard" tests below, so this test deliberately carries no hardcoded upper bound.
  // A fixed ceiling would break on the next legitimate append and force a hand-edit every release.
  test('every versionAdded is a valid, non-zero semver', () => {
    for (const entry of REMEDIATION_RUNBOOK_DOCUMENTS) {
      expect(() => compareVersions(entry.versionAdded, '0.0.0')).not.toThrow();
      expect(compareVersions(entry.versionAdded, '0.0.0')).toBeGreaterThan(0);
    }
  });
});

describe('runbook catalogue completeness guard', () => {
  // The emitted and chunked document set is derived entirely from REMEDIATION_RUNBOOK_DOCUMENTS, so a
  // runbook whose YAML ships under source/remediation_runbooks but whose list entry was forgotten is
  // silently never emitted and no other test fails. This guard uses the YAML files on disk as the
  // independent source of truth: RemediationRunbookStack emits ASR-<name> from a <name>.yaml, so every
  // runbook document file must map to a list entry of the same name.
  const remediationRunbooksDir = join(__dirname, '..', 'remediation_runbooks');

  // Runbook YAML files intentionally absent from REMEDIATION_RUNBOOK_DOCUMENTS. Empty today: the shared
  // catalogue and the directory are a strict 1:1, and role-only remediations (e.g. TerminateEC2Instance)
  // ship no YAML here so they need no exclusion. Add a filename only alongside a note explaining why its
  // document is intentionally not emitted, so a genuinely forgotten entry still fails loudly.
  const UNLISTED_YAML_ALLOWLIST: readonly string[] = [];

  test('every runbook YAML on disk has a REMEDIATION_RUNBOOK_DOCUMENTS entry', () => {
    const listedNames = new Set(REMEDIATION_RUNBOOK_DOCUMENTS.map((entry) => entry.name));
    const yamlFiles = readdirSync(remediationRunbooksDir).filter((file) => file.endsWith('.yaml'));

    const unlisted = yamlFiles
      .filter((file) => !UNLISTED_YAML_ALLOWLIST.includes(file))
      .filter((file) => !listedNames.has(basename(file, '.yaml')));

    const guidance =
      unlisted.length === 0
        ? ''
        : `These runbook YAML files have no REMEDIATION_RUNBOOK_DOCUMENTS entry and will never be ` +
          `emitted: ${unlisted.join(', ')}. Append an entry (name without the .yaml suffix, a strictly ` +
          `higher versionAdded) to source/lib/remediation-runbooks.ts, or, if the document is ` +
          `intentionally not emitted, add the filename to UNLISTED_YAML_ALLOWLIST with a reason.`;
    expect(guidance).toBe('');
  });
});

describe('chunkRunbooks', () => {
  const entriesOf = (count: number): RemediationRunbookEntry[] =>
    Array.from({ length: count }, (_, i) => ({ name: `Runbook${i}`, versionAdded: '2.1.0' }));

  test('a non-finite limit yields a single chunk holding every document', () => {
    const chunks = chunkRunbooks(REMEDIATION_RUNBOOK_DOCUMENTS, Infinity);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(REMEDIATION_RUNBOOK_DOCUMENTS.length);
  });

  test('a limit equal to the length yields one full chunk', () => {
    const chunks = chunkRunbooks(REMEDIATION_RUNBOOK_DOCUMENTS, 79);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(79);
  });

  test('a remainder limit splits into boundary-correct chunks', () => {
    const chunks = chunkRunbooks(REMEDIATION_RUNBOOK_DOCUMENTS, 40);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]).toHaveLength(40);
    expect(chunks[1]).toHaveLength(39);
    expect(chunks[0]).toEqual(REMEDIATION_RUNBOOK_DOCUMENTS.slice(0, 40));
    expect(chunks[1]).toEqual(REMEDIATION_RUNBOOK_DOCUMENTS.slice(40, 80));
  });

  test('an exact-multiple limit splits into equal chunks', () => {
    const synthetic = entriesOf(80);
    const chunks = chunkRunbooks(synthetic, 40);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]).toHaveLength(40);
    expect(chunks[1]).toHaveLength(40);
  });

  test('chunk i equals slice(i*limit, i*limit + limit)', () => {
    const synthetic = entriesOf(25);
    const limit = 10;
    const chunks = chunkRunbooks(synthetic, limit);
    chunks.forEach((chunk, i) => {
      expect(chunk).toEqual(synthetic.slice(i * limit, i * limit + limit));
    });
  });
});

describe('append-only guard', () => {
  test('chunk 0 at the configured limit matches the frozen golden prefix exactly', () => {
    const chunk0 = chunkRunbooks(REMEDIATION_RUNBOOK_DOCUMENTS, getMemberStackLimit('runbook'))[0];
    expect(chunk0.map((entry) => entry.name)).toEqual(GOLDEN_CHUNK0_NAMES);
  });

  test('any future entry beyond the limit outranks the whole golden prefix', () => {
    const limit = getMemberStackLimit('runbook');
    const goldenPrefix = REMEDIATION_RUNBOOK_DOCUMENTS.slice(0, limit);
    const maxGoldenVersion = goldenPrefix
      .map((entry) => entry.versionAdded)
      .reduce((max, version) => (compareVersions(version, max) > 0 ? version : max), '0.0.0');
    const futureEntries = REMEDIATION_RUNBOOK_DOCUMENTS.slice(limit);
    for (const entry of futureEntries) {
      expect(compareVersions(entry.versionAdded, maxGoldenVersion)).toBeGreaterThan(0);
    }
  });
});

describe('metadata/stack drift guard', () => {
  const emittedDocumentNames = (props: { runbookStackIndex?: number; runbookChunkLimit?: number }): string[] => {
    const app = new App();
    const roleStack = new MemberRolesStack(app, 'roles', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
    });
    const stack = new RemediationRunbookStack(app, 'stack', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
      ssmdocs: 'remediation_runbooks',
      roleStack,
      parameters: { Namespace: 'myNamespace' },
      ...props,
    });

    const template = Template.fromStack(stack);
    const documents = template.findResources('AWS::SSM::Document');
    return Object.values(documents).map((doc) => {
      const name = doc.Properties.Name;
      if (typeof name !== 'string') {
        throw new Error(`Expected an SSM document Name of type string, received ${typeof name}`);
      }
      return name.replace(/^ASR-/, '');
    });
  };

  test('a chunked stack emits only the documents in its own slice', () => {
    const limit = 40;
    const chunks = chunkRunbooks(REMEDIATION_RUNBOOK_DOCUMENTS, limit);

    const firstChunkNames = emittedDocumentNames({ runbookStackIndex: 0, runbookChunkLimit: limit });
    expect(new Set(firstChunkNames)).toEqual(new Set(chunks[0].map((entry) => entry.name)));

    const secondChunkNames = emittedDocumentNames({ runbookStackIndex: 1, runbookChunkLimit: limit });
    expect(new Set(secondChunkNames)).toEqual(new Set(chunks[1].map((entry) => entry.name)));

    // The split is a partition: every document lands in exactly one chunk, none is dropped.
    expect(firstChunkNames.length + secondChunkNames.length).toBe(REMEDIATION_RUNBOOK_DOCUMENTS.length);
  });
});

describe('multi-chunk synthesis (cross-app regression)', () => {
  const CHUNK_LIMIT = 40;

  // Wire a two-chunk stack graph exactly as solution_deploy.ts does: one shared MemberRolesStack and
  // one RemediationRunbookStack per document chunk, ids derived from the same shared helpers.
  const buildTwoChunkApp = (outdir: string): App => {
    const app = new App({ outdir });
    const roleStack = new MemberRolesStack(app, 'MemberRolesStack', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
    });
    const stackCount = runbookStackCount(CHUNK_LIMIT);
    expect(stackCount).toBe(2);
    for (let index = 0; index < stackCount; index++) {
      new RemediationRunbookStack(app, `RunbookStack${runbookStackSuffix(index)}`, {
        synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
        description: 'test;',
        solutionId: 'SO0111',
        solutionVersion: 'v1.1.1',
        solutionDistBucket: 'sharrbukkit',
        ssmdocs: 'remediation_runbooks',
        roleStack,
        runbookStackIndex: index,
        runbookChunkLimit: CHUNK_LIMIT,
        parameters: { Namespace: 'myNamespace' },
      });
    }
    return app;
  };

  test('a real two-chunk synth has no cross-app role scope and keeps all roles in the shared stack', () => {
    // Every chunk's role constructs must resolve within the one shared app. This needs a real
    // app.synth plus the beforeExit hook rather than Template.fromStack: Template.fromStack
    // isolates a single stack and never fires CDK's auto-synth beforeExit hook (which the CDK CLI
    // arms by setting CDK_OUTDIR), so it cannot surface a cross-app reference. Setting CDK_OUTDIR
    // and firing beforeExit forces every stack to resolve, so an unresolved cross-app reference
    // surfaces here as CannotReferenceAcrossApps.
    const previousOutdir = process.env.CDK_OUTDIR;
    process.env.CDK_OUTDIR = mkdtempSync(join(tmpdir(), 'asr-cdk-outdir-'));
    try {
      const app = buildTwoChunkApp(mkdtempSync(join(tmpdir(), 'asr-assembly-')));
      const assembly = app.synth();
      expect(() => process.emit('beforeExit', 0)).not.toThrow();

      // The assembly holds exactly the shared roles stack and the two document chunks.
      const stackNames = assembly.stacks.map((stack) => stack.stackName).sort();
      expect(stackNames).toEqual(['MemberRolesStack', 'RunbookStack', 'RunbookStack1']);

      // All roles live in the shared stack, including remediations that fall in chunk 1.
      const rolesTemplateJson = JSON.stringify(assembly.getStackByName('MemberRolesStack').template);
      for (const chunkOneRole of ['SO0111-EnableMacie', 'SO0111-TightenResourcePolicy']) {
        expect(rolesTemplateJson).toContain(chunkOneRole);
      }

      // Each document chunk carries SSM documents only, with no IAM roles and no cross-stack
      // references back to the roles stack, because all roles live in the shared MemberRolesStack.
      for (const runbookStackName of ['RunbookStack', 'RunbookStack1']) {
        const stackArtifact = assembly.getStackByName(runbookStackName);
        Template.fromJSON(stackArtifact.template).resourceCountIs('AWS::IAM::Role', 0);
        const templateJson = JSON.stringify(stackArtifact.template);
        expect(templateJson).not.toContain('Fn::ImportValue');
        expect(templateJson).not.toContain('Fn::GetAtt');
      }
    } finally {
      if (previousOutdir === undefined) {
        delete process.env.CDK_OUTDIR;
      } else {
        process.env.CDK_OUTDIR = previousOutdir;
      }
    }
  });
});
