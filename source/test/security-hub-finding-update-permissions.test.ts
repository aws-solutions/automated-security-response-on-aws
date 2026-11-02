// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, NestedStack, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { AdministratorStack } from '../lib/administrator-stack';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { RemediationRunbookStack } from '../lib/remediation-runbook-stack';

interface PolicyStatementJson {
  readonly Sid?: string;
  readonly Effect: 'Allow' | 'Deny';
  readonly Action: string | string[];
  readonly Resource?: unknown;
  readonly Condition?: Record<string, Record<string, unknown>>;
}

interface NamedPolicyDocument {
  readonly policyName: string;
  readonly statements: PolicyStatementJson[];
}

interface InlinePolicyJson {
  readonly PolicyName: string;
  readonly PolicyDocument: { readonly Statement: PolicyStatementJson[] };
}

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

function actionsOf(statement: PolicyStatementJson): string[] {
  return Array.isArray(statement.Action) ? statement.Action : [statement.Action];
}

function grantsBatchUpdateFindings(document: NamedPolicyDocument): boolean {
  return document.statements.some(
    (statement) => statement.Effect === 'Allow' && actionsOf(statement).includes(BATCH_UPDATE_FINDINGS),
  );
}

/** Every IAM policy document in a template: standalone policies, managed policies, and role inline policies. */
function policyDocumentsOf(template: Template): NamedPolicyDocument[] {
  const standalonePolicies = [
    ...Object.values(template.findResources('AWS::IAM::Policy')),
    ...Object.values(template.findResources('AWS::IAM::ManagedPolicy')),
  ].map((resource) => ({
    policyName: JSON.stringify(resource.Properties.PolicyName ?? resource.Properties.ManagedPolicyName),
    statements: resource.Properties.PolicyDocument.Statement as PolicyStatementJson[],
  }));
  const roleInlinePolicies = Object.values(template.findResources('AWS::IAM::Role')).flatMap((role) =>
    ((role.Properties.Policies ?? []) as InlinePolicyJson[]).map((policy) => ({
      policyName: JSON.stringify(role.Properties.RoleName) + '/' + policy.PolicyName,
      statements: policy.PolicyDocument.Statement,
    })),
  );
  return [...standalonePolicies, ...roleInlinePolicies];
}

/** Templates of a stack and of every nested stack beneath it. */
function templatesOf(stack: Stack): Template[] {
  const nestedStacks = stack.node.findAll().filter((child): child is NestedStack => NestedStack.isNestedStack(child));
  return [stack, ...nestedStacks].map((each) => Template.fromStack(each));
}

function memberPolicyDocuments(): NamedPolicyDocument[] {
  const app = new App();
  const roleStack = new MemberRolesStack(app, 'roles', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
  });
  // The remediation runbook stack places its per-control roles and policies in the role stack.
  new RemediationRunbookStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'remediation_runbooks',
    roleStack,
    parameters: { Namespace: 'myNamespace' },
  });
  return policyDocumentsOf(Template.fromStack(roleStack));
}

function administratorPolicyDocuments(): NamedPolicyDocument[] {
  const stack = new AdministratorStack(new App(), 'TestStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    env: { account: '111111111111', region: 'us-east-1' },
    solutionId: 'SO0111',
    solutionVersion: 'v3.1.0',
    solutionDistBucket: 'solutions',
    solutionTMN: 'automated-security-response-on-aws',
    solutionName: 'AWS Security Hub Automated Response & Remediation',
    runtimePython: Runtime.PYTHON_3_11,
    orchestratorLogGroup: 'ORCH_LOG_GROUP',
    SNSTopicName: 'ASR_Topic',
    cloudTrailLogGroupName: 'cloudtrail-logs',
  });
  return templatesOf(stack).flatMap(policyDocumentsOf);
}

describe('Security Hub finding update permissions', () => {
  const findingUpdatePolicies = [...memberPolicyDocuments(), ...administratorPolicyDocuments()].filter(
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
