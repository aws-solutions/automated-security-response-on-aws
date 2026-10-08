// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import { apiLambdaEnvironment } from '../apiLambdaEnvironment';

/** Resolved member-account credentials, in the shape AWS SDK clients accept. */
export interface MemberCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

const SOLUTION_PREFIX = 'SO0111';
const ADMIN_ROLE_NAME = `${SOLUTION_PREFIX}-ASR-Orchestrator-Admin`;
const MEMBER_ROLE_NAME = `${SOLUTION_PREFIX}-ASR-Orchestrator-Member`;
const SESSION_DURATION_SECONDS = 900;

/** STS caps RoleSessionName at 64 chars and allows only [\w+=,.@-]. */
const MAX_ROLE_SESSION_NAME_LENGTH = 64;

/**
 * Builds a member-account RoleSessionName for a custom-runbook operation,
 * carrying the acting principal so the member account's CloudTrail can attribute
 * the IAM/SSM changes to a human. The actor is sanitized to STS's allowed
 * character set and the whole name truncated to 64 chars; when no actor is known
 * the bare operation name is used.
 */
export function buildMemberSessionName(operation: string, actor?: string): string {
  const base = `asr-cr-${operation}`;
  if (!actor) return base.slice(0, MAX_ROLE_SESSION_NAME_LENGTH);
  const sanitizedActor = actor.replace(/[^\w+=,.@-]/g, '-');
  return `${base}-${sanitizedActor}`.slice(0, MAX_ROLE_SESSION_NAME_LENGTH);
}

/**
 * Hands out short-lived member-account credentials over the solution's existing
 * cross-account trust chain:
 *
 *   API Lambda → SO0111-ASR-Orchestrator-Admin (same account)
 *               → SO0111-ASR-Orchestrator-Member (member account)
 *
 * Both the remediation role provisioning and the copy-per-member SSM document
 * deployment need member-account credentials, so the chain lives here rather
 * than being duplicated per service.
 */
export class MemberAccountCredentialsProvider {
  private stsClient: STSClient | undefined;

  constructor(private readonly stsClientFactory: () => STSClient = () => new STSClient({ maxAttempts: 3 })) {}

  private getStsClient(): STSClient {
    this.stsClient ??= this.stsClientFactory();
    return this.stsClient;
  }

  /**
   * Assume into a member account. `sessionName` identifies the caller in both the
   * admin and member accounts' CloudTrail, so pass something specific to the
   * operation.
   */
  async getCredentials(memberAccountId: string, sessionName: string): Promise<MemberCredentials> {
    const { AWS_ACCOUNT_ID, AWS_PARTITION } = apiLambdaEnvironment();

    const adminRoleArn = `arn:${AWS_PARTITION}:iam::${AWS_ACCOUNT_ID}:role/${ADMIN_ROLE_NAME}`;
    const adminCreds = await this.getStsClient().send(
      new AssumeRoleCommand({
        RoleArn: adminRoleArn,
        RoleSessionName: sessionName,
        DurationSeconds: SESSION_DURATION_SECONDS,
      }),
    );
    if (!adminCreds.Credentials) {
      throw new Error(`Failed to assume Orchestrator Admin role ${adminRoleArn} in account ${AWS_ACCOUNT_ID}`);
    }

    const adminSts = new STSClient({
      credentials: toCredentialIdentity(adminCreds.Credentials),
    });

    const memberRoleArn = `arn:${AWS_PARTITION}:iam::${memberAccountId}:role/${MEMBER_ROLE_NAME}`;
    const memberCreds = await adminSts.send(
      new AssumeRoleCommand({
        RoleArn: memberRoleArn,
        RoleSessionName: sessionName,
        DurationSeconds: SESSION_DURATION_SECONDS,
      }),
    );
    if (!memberCreds.Credentials) {
      throw new Error(`Failed to assume Orchestrator Member role ${memberRoleArn} in account ${memberAccountId}`);
    }

    return toCredentialIdentity(memberCreds.Credentials);
  }
}

function toCredentialIdentity(credentials: {
  AccessKeyId?: string;
  SecretAccessKey?: string;
  SessionToken?: string;
}): MemberCredentials {
  const { AccessKeyId, SecretAccessKey, SessionToken } = credentials;
  if (!AccessKeyId || !SecretAccessKey) throw new Error('AssumeRole returned incomplete credentials');
  return { accessKeyId: AccessKeyId, secretAccessKey: SecretAccessKey, sessionToken: SessionToken };
}
