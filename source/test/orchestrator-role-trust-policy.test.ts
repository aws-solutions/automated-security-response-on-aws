// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, NestedStack, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AdministratorStack } from '../lib/administrator-stack';

/*
 * The WebUI API Lambda assumes SO0111-ASR-Orchestrator-Admin to deploy a custom runbook.
 * Role chaining needs a grant on both sides, and the trust side is the one that is easy to
 * lose: the role is declared with a Lambda service principal, which reads as complete.
 *
 * Both halves are asserted here because either one alone produces the same opaque runtime
 * failure — "not authorized to perform: sts:AssumeRole on resource:
 * .../SO0111-ASR-Orchestrator-Admin" — from deploy_runbook, with no indication of which
 * side is missing. A deployment carrying only one half looks healthy until a customer
 * tries to release a custom runbook to a member account.
 */
describe('Orchestrator admin role trust policy', () => {
  const administratorStack = (): Stack =>
    new AdministratorStack(new App(), 'TestStack', {
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

  /** The Web UI nested stack, where the API Lambda and its role are declared. */
  const webUiNestedStackTemplate = (stack: Stack): Template => {
    const nested = stack.node
      .findAll()
      .find((child): child is NestedStack => NestedStack.isNestedStack(child) && child.node.id === 'WebUINestedStack');
    if (!nested) throw new Error('WebUINestedStack not found in the administrator stack');
    return Template.fromStack(nested);
  };

  /**
   * The statements of one synthesized IAM policy resource, or none when it carries no
   * document. Typed rather than reaching through `any`: a synthesized template is untyped
   * JSON, so the shape is narrowed here once instead of being asserted away per call site.
   */
  interface PolicyResource {
    readonly Properties?: { readonly PolicyDocument?: { readonly Statement?: unknown } };
  }

  const policyStatements = (resource: PolicyResource): unknown[] => {
    const statements = resource.Properties?.PolicyDocument?.Statement;
    return Array.isArray(statements) ? (statements as unknown[]) : [];
  };

  const orchestratorTrustPolicy = () => {
    const roles = Template.fromStack(administratorStack()).findResources('AWS::IAM::Role', {
      Properties: { RoleName: 'SO0111-ASR-Orchestrator-Admin' },
    });
    const logicalIds = Object.keys(roles);
    expect(logicalIds).toHaveLength(1);
    return roles[logicalIds[0]].Properties.AssumeRolePolicyDocument.Statement;
  };

  test('lets a role from this stack assume it, so the API Lambda can chain into it', () => {
    const statements = orchestratorTrustPolicy();

    const accountTrust = statements.find((statement: { Principal: { AWS?: unknown } }) => statement.Principal.AWS);
    expect(accountTrust).toBeDefined();
    expect(accountTrust.Action).toBe('sts:AssumeRole');
    expect(accountTrust.Effect).toBe('Allow');
  });

  test('restricts that trust to the API Lambda execution role by its exact name', () => {
    const statements = orchestratorTrustPolicy();

    const accountTrust = statements.find((statement: { Principal: { AWS?: unknown } }) => statement.Principal.AWS);
    // Pinned to the API Lambda's exact role ARN, not a broad name pattern, so the trust
    // scopes to that one role.
    const principalCondition = JSON.stringify(accountTrust.Condition.ArnLike['aws:PrincipalArn']);
    expect(principalCondition).toContain(':role/SO0111-ASR-APIs-Role');
    expect(principalCondition).not.toContain('AWS::StackName');
    expect(principalCondition).not.toContain('*');
  });

  test('still trusts the Lambda service, which the orchestrator functions run as', () => {
    const statements = orchestratorTrustPolicy();

    expect(
      statements.some(
        (statement: { Principal: { Service?: string } }) => statement.Principal.Service === 'lambda.amazonaws.com',
      ),
    ).toBe(true);
  });

  test('the API Lambda holds the identity-side grant the trust condition assumes', () => {
    // The trust statement deliberately delegates to the account and relies on only the
    // API Lambda holding an identity grant naming this role. That argument collapses if
    // the grant is dropped: the trust would then be the only gate, and the deploy would
    // fail closed with the same message it fails with when the trust is missing.
    // Both resource types are searched: the API Lambda's inline policy sits at the IAM
    // size limit, so CDK spills later statements into an attached "OverflowPolicy"
    // managed policy. Searching only AWS::IAM::Policy reports this grant as missing while
    // it is merely in the overflow — verified against a deployed stack, where the grant
    // lives in the managed policy and the inline one has no sts statement at all.
    const template = webUiNestedStackTemplate(administratorStack());
    const assumeRoleGrants = [
      ...Object.values(template.findResources('AWS::IAM::Policy')),
      ...Object.values(template.findResources('AWS::IAM::ManagedPolicy')),
    ]
      .flatMap(policyStatements)
      .filter((statement) => JSON.stringify(statement).includes('ASR-Orchestrator-Admin'));

    // One statement names the role, and it is exactly the grant the trust relies on. A
    // rendered-substring check here would still count a statement whose Effect had become
    // Deny, whose Action had widened to `sts:*` or gained siblings, or whose Resource had
    // become `*` with the role name surviving only in a Condition — each of which breaks
    // the argument above while keeping both substrings present. `toEqual` on the whole
    // statement rejects all of them, and an added key such as Condition or NotAction too.
    expect(assumeRoleGrants).toEqual([
      {
        Effect: 'Allow',
        Action: 'sts:AssumeRole',
        Resource: {
          'Fn::Join': [
            '',
            ['arn:', { Ref: 'AWS::Partition' }, ':iam::111111111111:role/SO0111-ASR-Orchestrator-Admin'],
          ],
        },
      },
    ]);
  });

  test('the API Lambda role name is pinned to the exact name the trust condition expects', () => {
    // The exact-ARN trust needs a deterministic name; api-construct.ts pins it. An
    // auto-generated name would not be predictable enough for the trust to reference.
    const roles = webUiNestedStackTemplate(administratorStack()).findResources('AWS::IAM::Role');
    const apiLambdaRoles = Object.entries(roles).filter(([logicalId]) =>
      logicalId.includes('ApiConstructAPILambdaServiceRole'),
    );

    expect(apiLambdaRoles).toHaveLength(1);
    expect(apiLambdaRoles[0][1].Properties?.RoleName).toBe('SO0111-ASR-APIs-Role');
  });
});
