// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, NestedStack, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { AdministratorStack } from '../lib/administrator-stack';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { MemberCloudTrailStack } from '../lib/member/cloud-trail';
import { MemberStack } from '../lib/member-stack';
import { OrchLogStack } from '../lib/orchestrator-log-stack';
import { RemediationRunbookStack } from '../lib/remediation-runbook-stack';

export interface PolicyStatementJson {
  readonly Sid?: string;
  readonly Effect: 'Allow' | 'Deny';
  readonly Action?: string | string[];
  readonly Resource?: unknown;
  readonly Condition?: Record<string, Record<string, unknown>>;
}

export interface NamedPolicyDocument {
  readonly policyName: string;
  readonly statements: PolicyStatementJson[];
}

interface InlinePolicyJson {
  readonly PolicyName: string;
  readonly PolicyDocument: { readonly Statement: PolicyStatementJson[] };
}

export function actionsOf(statement: PolicyStatementJson): string[] {
  if (statement.Action === undefined) return [];
  return Array.isArray(statement.Action) ? statement.Action : [statement.Action];
}

/**
 * Every IAM policy document in a template: standalone policies, managed policies, and role inline policies.
 * The casts are the boundary where the untyped template JSON from `Template.findResources` gets a shape.
 */
export function policyDocumentsOf(template: Template): NamedPolicyDocument[] {
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

function templatesOf(stack: Stack): Template[] {
  const nestedStacks = stack.node.findAll().filter((child): child is NestedStack => NestedStack.isNestedStack(child));
  return [stack, ...nestedStacks].map((each) => Template.fromStack(each));
}

export function memberRolesPolicyDocuments(): NamedPolicyDocument[] {
  const app = new App();
  const roleStack = new MemberRolesStack(app, 'roles', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionTradeMarkName: 'automated-security-response-on-aws',
    runtimePython: Runtime.PYTHON_3_11,
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

export function memberPolicyDocuments(): NamedPolicyDocument[] {
  const stack = new MemberStack(new App(), 'MemberStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    resourceNamePrefix: 'SO0111',
    solutionTradeMarkName: 'automated-security-response-on-aws',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    runtimePython: Runtime.PYTHON_3_11,
    SNSTopicName: 'ASR_Topic',
    cloudTrailLogGroupName: 'SO0111-ASR-CloudTrailEvents',
  });
  return templatesOf(stack).flatMap(policyDocumentsOf);
}

export function administratorPolicyDocuments(): NamedPolicyDocument[] {
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

/** Policies of the standalone stacks the solution deploys beside the administrator and member stacks. */
export function auxiliaryStackPolicyDocuments(): NamedPolicyDocument[] {
  const app = new App();
  const synthesizer = new DefaultStackSynthesizer({ generateBootstrapVersionRule: false });
  const cloudTrailStack = new MemberCloudTrailStack(app, 'MemberCloudTrailStack', { synthesizer });
  const orchestratorLogStack = new OrchLogStack(app, 'OrchestratorLogStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    logGroupName: 'ORCH_LOG_GROUP',
    solutionId: 'SO0111',
  });
  return [cloudTrailStack, orchestratorLogStack].flatMap(templatesOf).flatMap(policyDocumentsOf);
}
