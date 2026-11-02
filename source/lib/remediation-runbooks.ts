// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Ordered, append-only catalogue of the shared remediation runbook SSM documents emitted by
 * {@link RemediationRunbookStack}, plus the chunker that assigns them to runbook nested stacks.
 *
 * The order of this list matches the source/creation order of the document-emitting blocks in
 * `remediation-runbook-stack.ts`. It is NOT sorted by `versionAdded`: source order is what keeps the
 * synthesized runbook template stable. `versionAdded` is metadata and the append-only key only. A
 * new runbook MUST be appended at the end with a strictly higher release version so an
 * already-shipped document never moves across a chunk boundary on an in-place upgrade (which would
 * collide on the fixed `ASR-<name>` physical name).
 */
export interface RemediationRunbookEntry {
  /** `ssmDocName`; also the construct-id suffix `'ASR ' + name` and physical name `'ASR-' + name`. */
  readonly name: string;
  /** Stable, append-only ordering key. New runbooks MUST use a strictly higher release version. */
  readonly versionAdded: string;
  /**
   * Retain-on-deprecate (house pattern): a deprecated runbook STILL emits its SSM document so a
   * stack update never deletes a deployed document. This flag is metadata only; it does not remove
   * the entry from the emitted/chunked set.
   */
  readonly deprecated?: boolean;
}

/**
 * The 79 document-emitting remediation runbooks in exact source/creation order. The 6 role-only
 * blocks (ConfigureS3BucketLogging, DisablePublicAccessForSecurityGroup, TerminateEC2Instance,
 * Inspector.InstanceVulnerability, GuardDuty.IAMUser, Macie.SensitiveDataS3Object) are not listed
 * here because they install only an IAM role/policy and emit no runbook document.
 */
export const REMEDIATION_RUNBOOK_DOCUMENTS: readonly RemediationRunbookEntry[] = [
  { name: 'CreateCloudTrailMultiRegionTrail', versionAdded: '2.1.0' },
  { name: 'CreateLogMetricFilterAndAlarm', versionAdded: '2.1.0' },
  { name: 'EnableAutoScalingGroupELBHealthCheck', versionAdded: '2.1.0' },
  { name: 'EnableAWSConfig', versionAdded: '2.1.0' },
  { name: 'EnableCloudTrailToCloudWatchLogging', versionAdded: '2.1.0' },
  { name: 'EnableCloudTrailEncryption', versionAdded: '2.1.0' },
  { name: 'EnableDefaultEncryptionS3', versionAdded: '2.1.0' },
  { name: 'EnableCFNTerminationProtection', versionAdded: '4.0.0' },
  { name: 'EnableS3BucketVersioning', versionAdded: '4.0.0' },
  { name: 'EnableVPCFlowLogs', versionAdded: '2.1.0' },
  { name: 'CreateAccessLoggingBucket', versionAdded: '2.1.0' },
  { name: 'MakeEBSSnapshotsPrivate', versionAdded: '2.1.0' },
  { name: 'MakeRDSSnapshotPrivate', versionAdded: '2.1.0' },
  { name: 'RemoveLambdaPublicAccess', versionAdded: '2.1.0' },
  { name: 'RevokeUnrotatedKeys', versionAdded: '2.1.0' },
  { name: 'SetSSLBucketPolicy', versionAdded: '2.1.0' },
  { name: 'ReplaceCodeBuildClearTextCredentials', versionAdded: '2.1.0' },
  { name: 'S3BlockDenylist', versionAdded: '2.1.0' },
  { name: 'EncryptRDSSnapshot', versionAdded: '2.1.0' },
  { name: 'DisablePublicAccessToRedshiftCluster', versionAdded: '2.1.0' },
  { name: 'EnableRedshiftClusterAuditLogging', versionAdded: '2.1.0' },
  { name: 'EnableAutomaticVersionUpgradeOnRedshiftCluster', versionAdded: '2.1.0' },
  { name: 'EnableAutomaticSnapshotsOnRedshiftCluster', versionAdded: '2.1.0' },
  { name: 'CreateIAMSupportRole', versionAdded: '2.1.0' },
  { name: 'EnableEncryptionForSQSQueue', versionAdded: '2.1.0' },
  { name: 'ConfigureSNSTopicForStack', versionAdded: '2.1.0' },
  { name: 'ConfigureS3BucketPublicAccessBlock', versionAdded: '2.1.0' },
  { name: 'ConfigureS3PublicAccessBlock', versionAdded: '2.1.0' },
  { name: 'EnableCloudTrailLogFileValidation', versionAdded: '2.1.0' },
  { name: 'EnableEbsEncryptionByDefault', versionAdded: '2.1.0' },
  { name: 'EnableEnhancedMonitoringOnRDSInstance', versionAdded: '2.1.0' },
  { name: 'EnableKeyRotation', versionAdded: '2.1.0' },
  { name: 'EnableRDSClusterDeletionProtection', versionAdded: '2.1.0' },
  { name: 'EnableCopyTagsToSnapshotOnRDSCluster', versionAdded: '2.1.0' },
  { name: 'EnableRDSInstanceDeletionProtection', versionAdded: '2.1.0' },
  { name: 'EnableMultiAZOnRDSInstance', versionAdded: '2.1.0' },
  { name: 'RemoveVPCDefaultSecurityGroupRules', versionAdded: '2.1.0' },
  { name: 'RevokeUnusedIAMUserCredentials', versionAdded: '2.1.0' },
  { name: 'SetIAMPasswordPolicy', versionAdded: '2.1.0' },
  { name: 'DisablePublicAccessToRDSInstance', versionAdded: '2.1.0' },
  { name: 'EnableMinorVersionUpgradeOnRDSDBInstance', versionAdded: '2.1.0' },
  { name: 'EnableEncryptionForSNSTopic', versionAdded: '2.1.0' },
  { name: 'EnableDeliveryStatusLoggingForSNSTopic', versionAdded: '2.1.0' },
  { name: 'DisablePublicIPAutoAssign', versionAdded: '2.1.0' },
  { name: 'EnableIMDSV2OnInstance', versionAdded: '2.1.0' },
  { name: 'RemoveCodeBuildPrivilegedMode', versionAdded: '2.1.0' },
  { name: 'EnableCloudFrontDefaultRootObject', versionAdded: '2.1.0' },
  { name: 'BlockSSMDocumentPublicAccess', versionAdded: '2.1.0' },
  { name: 'EnableSSMDocumentBlockPublicSharing', versionAdded: '4.0.0' },
  { name: 'AttachSSMPermissionsToEC2', versionAdded: '2.2.0' },
  { name: 'AttachServiceVPCEndpoint', versionAdded: '2.2.0' },
  { name: 'EnableBucketEventNotifications', versionAdded: '2.1.0' },
  { name: 'ConfigureDynamoDBAutoScaling', versionAdded: '2.3.0' },
  { name: 'EnableDynamoDBDeletionProtection', versionAdded: '2.3.0' },
  { name: 'EnableElastiCacheBackups', versionAdded: '2.3.0' },
  { name: 'EnforceHTTPSForALB', versionAdded: '2.3.0' },
  { name: 'LimitECSRootFilesystemAccess', versionAdded: '2.3.0' },
  { name: 'EnableElastiCacheReplicationGroupFailover', versionAdded: '2.3.0' },
  { name: 'EnableElastiCacheVersionUpgrades', versionAdded: '2.3.0' },
  { name: 'SetCloudFrontOriginDomain', versionAdded: '2.1.0' },
  { name: 'DisableUnrestrictedAccessToHighRiskPorts', versionAdded: '2.1.0' },
  { name: 'EnablePrivateRepositoryScanning', versionAdded: '2.1.0' },
  { name: 'SetS3LifecyclePolicy', versionAdded: '2.1.0' },
  { name: 'UpdateSecretRotationPeriod', versionAdded: '2.1.0' },
  { name: 'DisableTGWAutoAcceptSharedAttachments', versionAdded: '2.1.0' },
  { name: 'EnableGuardDuty', versionAdded: '2.1.0' },
  { name: 'TagDynamoDBTableResource', versionAdded: '2.3.0' },
  { name: 'TagGuardDutyResource', versionAdded: '2.2.0' },
  { name: 'EnableAutoSecretRotation', versionAdded: '2.1.0' },
  { name: 'RevokeUnauthorizedInboundRules', versionAdded: '2.1.0' },
  { name: 'RemoveUnusedSecret', versionAdded: '2.1.0' },
  { name: 'SetLogGroupRetentionDays', versionAdded: '2.2.0' },
  { name: 'EnableAPIGatewayCacheDataEncryption', versionAdded: '2.2.0' },
  { name: 'ConfigureAutoScalingLaunchConfigToRequireIMDSv2', versionAdded: '2.2.0' },
  { name: 'ConfigureAutoScalingLaunchConfigNoPublicIP', versionAdded: '2.2.0' },
  { name: 'EnableMacie', versionAdded: '2.2.0' },
  { name: 'EnableAPIGatewayExecutionLogs', versionAdded: '2.2.0' },
  { name: 'EnableAthenaWorkGroupLogging', versionAdded: '2.2.0' },
  { name: 'TightenResourcePolicy', versionAdded: '4.0.0' },
];

/**
 * Partition the ordered runbook documents into per-stack chunks. Mirrors the slice math and naming
 * of `playbooks/split_member_stacks.ts`: a non-finite `stackLimit` yields a single chunk holding
 * every document; otherwise chunk `i` owns `slice(i*stackLimit, i*stackLimit + stackLimit)`, so
 * chunk 0 is the frozen prefix and each later chunk only ever holds newer, appended documents.
 */
export function chunkRunbooks(
  runbookDocuments: readonly RemediationRunbookEntry[],
  stackLimit: number,
): RemediationRunbookEntry[][] {
  const hasFiniteLimit = Number.isFinite(stackLimit);
  const numChunks = hasFiniteLimit ? Math.ceil(runbookDocuments.length / stackLimit) : 1;
  const size = hasFiniteLimit ? stackLimit : runbookDocuments.length;
  return Array.from({ length: numChunks }, (_, i) => runbookDocuments.slice(i * size, i * size + size));
}

/**
 * How many runbook stacks a given per-stack document `stackLimit` produces. Single source of truth
 * for the two call sites that must agree: `solution_deploy.ts` (which synthesizes the stacks) and
 * `member-stack.ts` (which references the templates those stacks emit). Both derive the count from
 * {@link chunkRunbooks} so they can never disagree on how many stacks exist.
 */
export function runbookStackCount(stackLimit: number): number {
  return chunkRunbooks(REMEDIATION_RUNBOOK_DOCUMENTS, stackLimit).length;
}

/**
 * The index suffix shared by the synthesized runbook stack ids and the template filenames the member
 * stack references: empty for chunk 0 and the index otherwise. Centralized so the synthesizing and
 * referencing call sites cannot drift apart.
 */
export function runbookStackSuffix(runbookStackIndex: number): string {
  return runbookStackIndex === 0 ? '' : String(runbookStackIndex);
}
