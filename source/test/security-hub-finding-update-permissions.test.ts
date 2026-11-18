// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  actionsOf,
  administratorPolicyDocuments,
  memberRolesPolicyDocuments,
  NamedPolicyDocument,
  PolicyStatementJson,
} from './iam-policy-documents';

const BATCH_UPDATE_FINDINGS = 'securityhub:BatchUpdateFindings';

const DENY_SUPPRESS_ASFF: PolicyStatementJson = {
  Sid: 'DenySuppressingFindingsAsff',
  Effect: 'Deny',
  Action: BATCH_UPDATE_FINDINGS,
  Resource: '*',
  Condition: { StringEquals: { 'securityhub:ASFFSyntaxPath/Workflow.Status': 'SUPPRESSED' } },
};

const DENY_SUPPRESS_OCSF: PolicyStatementJson = {
  Sid: 'DenySuppressingFindingsOcsf',
  Effect: 'Deny',
  Action: BATCH_UPDATE_FINDINGS,
  Resource: '*',
  Condition: { StringEquals: { 'securityhub:OCSFSyntaxPath/StatusId': '3' } },
};

function grantsBatchUpdateFindings(document: NamedPolicyDocument): boolean {
  return document.statements.some(
    (statement) => statement.Effect === 'Allow' && actionsOf(statement).includes(BATCH_UPDATE_FINDINGS),
  );
}

describe('Security Hub finding update permissions', () => {
  const findingUpdatePolicies = [...memberRolesPolicyDocuments(), ...administratorPolicyDocuments()].filter(
    grantsBatchUpdateFindings,
  );

  test('covers every role that updates findings', () => {
    const policyNames = findingUpdatePolicies.map((document) => document.policyName);

    // Per-control policy names are CDK-generated from the construct id, hence the unhyphenated form.
    expect(policyNames).toEqual(
      expect.arrayContaining([
        expect.stringContaining('SO0111-ASR-Orchestrator-Member'),
        expect.stringContaining('SO0111-ASR_Orchestrator_Notifier'),
        expect.stringContaining('ASRRemediationPolicyInspectorInstanceVulnerability'),
        expect.stringContaining('ASRRemediationPolicyGuardDutyIAMUser'),
        expect.stringContaining('ASRRemediationPolicyMacieSensitiveDataS3Object'),
      ]),
    );
  });

  test.each([
    ['ASFF Workflow.Status', DENY_SUPPRESS_ASFF],
    ['OCSF StatusId', DENY_SUPPRESS_OCSF],
  ])('every policy granting BatchUpdateFindings denies setting %s to suppressed', (_shape, denyStatement) => {
    for (const document of findingUpdatePolicies) {
      expect({ policyName: document.policyName, statements: document.statements }).toEqual({
        policyName: document.policyName,
        statements: expect.arrayContaining([denyStatement]),
      });
    }
  });

  test('BatchUpdateFindings is granted in a statement of its own', () => {
    const grants = findingUpdatePolicies.flatMap((document) =>
      document.statements.filter(
        (statement) => statement.Effect === 'Allow' && actionsOf(statement).includes(BATCH_UPDATE_FINDINGS),
      ),
    );

    for (const grant of grants) {
      expect(grant.Action).toBe(BATCH_UPDATE_FINDINGS);
    }
  });

  test('Orchestrator-Member publishes metrics only to the ASR namespace', () => {
    const memberPolicy = findingUpdatePolicies.find((document) =>
      document.policyName.includes('SO0111-ASR-Orchestrator-Member'),
    );
    const metricGrants = (memberPolicy?.statements ?? []).filter((statement) =>
      actionsOf(statement).includes('cloudwatch:PutMetricData'),
    );

    expect(metricGrants).toEqual([
      {
        Effect: 'Allow',
        Action: 'cloudwatch:PutMetricData',
        Resource: '*',
        Condition: { StringEquals: { 'cloudwatch:namespace': 'ASR' } },
      },
    ]);
  });
});
