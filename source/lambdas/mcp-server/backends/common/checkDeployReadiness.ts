// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { SSMClient, DescribeDocumentCommand, ListDocumentsCommand } from '@aws-sdk/client-ssm';
import { IAMClient, GetRoleCommand } from '@aws-sdk/client-iam';
import type { Executor } from '../types';
import type { CheckDeployReadinessParams } from '@asr/data-models';
import { MissingParameterError } from './errors';
import { isDocumentNotFound } from './ssmExecutionHelpers';

const RESOURCE_NAME_PREFIX = 'SO0111';
const MAX_PAGES = 50;

export interface ReadinessCheck {
  readonly check: string;
  readonly status: 'PASS' | 'FAIL';
  readonly detail: string;
  /** True when the SC-wrapper scan stopped at its page ceiling. */
  readonly truncated?: boolean;
}

async function checkChildDocument(ssm: SSMClient, remediationName: string): Promise<ReadinessCheck> {
  const documentName = `ASR-${remediationName}`;
  try {
    const response = await ssm.send(new DescribeDocumentCommand({ Name: documentName }));
    const documentStatus = response.Document?.Status;
    if (documentStatus !== 'Active') {
      return {
        check: 'child-document',
        status: 'FAIL',
        detail:
          `${documentName} exists but its status is ${documentStatus ?? 'unknown'}, not Active` +
          `${response.Document?.StatusInformation ? `: ${response.Document.StatusInformation}` : ''}. ` +
          'Wait for it to finish provisioning, or redeploy it if it failed.',
      };
    }
    return { check: 'child-document', status: 'PASS', detail: `${documentName} exists and is Active` };
  } catch (error) {
    if (isDocumentNotFound(error)) {
      return {
        check: 'child-document',
        status: 'FAIL',
        detail: `${documentName} not found. Deploy with: deploy_runbook({ service_name: "${remediationName}", ... })`,
      };
    }
    throw error;
  }
}

async function checkIamRole(
  iam: IAMClient,
  remediationName: string,
  namespace: string,
  controlId: string,
): Promise<ReadinessCheck> {
  const roleName = `${RESOURCE_NAME_PREFIX}-${remediationName}-${namespace}`;
  try {
    await iam.send(new GetRoleCommand({ RoleName: roleName }));
    return { check: 'iam-role', status: 'PASS', detail: `${roleName} exists` };
  } catch (error) {
    if (error instanceof Error && error.name === 'NoSuchEntityException') {
      return {
        check: 'iam-role',
        status: 'FAIL',
        detail:
          `${roleName} not found. Run deploy_runbook with required_iam_actions for control ` +
          `"${controlId}" — it provisions this role in each member account alongside the SSM document.`,
      };
    }
    throw error;
  }
}

async function findSecurityControlWrapperDocument(
  ssm: SSMClient,
  controlId: string,
): Promise<{ readonly matchedName: string | undefined; readonly truncated: boolean }> {
  // The SC standard version is not available to this Lambda (it is not in the
  // ExecutionContext or the MCP env), so the exact document name
  // `ASR-SC_<version>_<controlId>` cannot be built for a DescribeDocument. Match by an
  // ANCHORED pattern instead of startsWith+endsWith: exactly one version segment
  // (`[^_]+`) and the whole control id at the end, so a control whose id is a suffix of
  // another (e.g. `S3.1` vs a hypothetical `X_S3.1`) cannot false-match. The control id
  // is regex-escaped because it contains a literal `.`.
  const wrapperNamePattern = new RegExp(`^ASR-SC_[^_]+_${escapeRegExp(controlId)}$`);
  let matchedName: string | undefined;
  let nextToken: string | undefined;
  let pages = 0;

  do {
    const response = await ssm.send(
      new ListDocumentsCommand({
        Filters: [
          { Key: 'DocumentType', Values: ['Automation'] },
          { Key: 'Owner', Values: ['Self'] },
          // Narrow the scan server-side to ASR-SC_ documents so the page budget is
          // spent on candidates, not every self-owned Automation document.
          { Key: 'Name', Values: ['ASR-SC_'] },
        ],
        MaxResults: 50,
        NextToken: nextToken,
      }),
    );
    matchedName = response.DocumentIdentifiers?.find(
      (documentIdentifier) => documentIdentifier.Name && wrapperNamePattern.test(documentIdentifier.Name),
    )?.Name;
    nextToken = response.NextToken;
    pages++;
  } while (!matchedName && nextToken && pages < MAX_PAGES);

  return { matchedName, truncated: !matchedName && Boolean(nextToken) };
}

/** Escape a string for safe embedding as a literal inside a RegExp. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function checkSecurityControlWrapper(ssm: SSMClient, controlId: string): Promise<ReadinessCheck> {
  const documentPrefix = 'ASR-SC_';
  const documentSuffix = `_${controlId}`;
  const { matchedName, truncated } = await findSecurityControlWrapperDocument(ssm, controlId);

  if (matchedName) {
    let response;
    try {
      response = await ssm.send(new DescribeDocumentCommand({ Name: matchedName }));
    } catch (error) {
      if (isDocumentNotFound(error)) {
        return {
          check: 'sc-wrapper',
          status: 'FAIL',
          detail:
            `SC wrapper ${matchedName} was listed but no longer exists. ` +
            'Run source_deploy to recreate it, then retry readiness.',
        };
      }
      throw error;
    }

    const documentStatus = response.Document?.Status;
    if (documentStatus !== 'Active') {
      return {
        check: 'sc-wrapper',
        status: 'FAIL',
        detail:
          `SC wrapper ${matchedName} exists but its status is ${documentStatus ?? 'unknown'}, not Active` +
          `${response.Document?.StatusInformation ? `: ${response.Document.StatusInformation}` : ''}. ` +
          'Wait for it to finish provisioning, or redeploy it if it failed.',
      };
    }
    return { check: 'sc-wrapper', status: 'PASS', detail: `SC wrapper for ${controlId} exists and is Active` };
  }

  return {
    check: 'sc-wrapper',
    status: 'FAIL',
    detail: truncated
      ? `No SC wrapper document found matching ${documentPrefix}*${documentSuffix} within the ` +
        `first ${MAX_PAGES} pages scanned — this account has more Automation documents than the scan covers, so ` +
        'absence is not confirmed. Re-run, or check manually with a targeted ssm list-documents call.'
      : `No SC wrapper document found matching ${documentPrefix}*${documentSuffix}. Run source_deploy to create it.`,
    truncated,
  };
}

export interface CheckDeployReadinessResult {
  readonly isReady: boolean;
  readonly checks: readonly ReadinessCheck[];
}

/**
 * Verify that the child document, IAM role, and optional Security Control wrapper
 * required by a built-in remediation are deployed and active.
 */
export const checkDeployReadiness: Executor<CheckDeployReadinessParams, CheckDeployReadinessResult> = async (
  args,
  context,
) => {
  const ssm = new SSMClient({ region: context.region });
  const iam = new IAMClient({ region: context.region });

  if (!args.namespace) {
    throw new MissingParameterError(
      'check_deploy_readiness',
      'namespace',
      'Pass the Namespace value from your ASR deployment.',
    );
  }

  const [childDocumentCheck, iamRoleCheck] = await Promise.all([
    checkChildDocument(ssm, args.remediation_name),
    checkIamRole(iam, args.remediation_name, args.namespace, args.control_id),
  ]);
  const checks: ReadinessCheck[] = [childDocumentCheck, iamRoleCheck];

  if (args.check_sc_wrapper !== false) {
    checks.push(await checkSecurityControlWrapper(ssm, args.control_id));
  }

  return {
    isReady: checks.every((check) => check.status === 'PASS'),
    checks,
  };
};
