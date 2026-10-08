// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { RunbookFactory } from '../lib/runbook_factory';
import { omitWaitResourceHash } from './utils';
import { RemediationRunbookStack } from '../lib/remediation-runbook-stack';

describe('MemberRolesStack tests', () => {
  function getRoleTestStack(): MemberRolesStack {
    const app = new App();
    return new MemberRolesStack(app, 'roles', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
    });
  }
  test('Global Roles Stack', () => {
    const stack = getRoleTestStack();
    const template = Template.fromStack(stack);

    const templateJSON = template.toJSON();
    omitWaitResourceHash(template, templateJSON);
    expect(templateJSON).toMatchSnapshot();
  });

  test('Orchestrator member role scopes automation-execution reads', () => {
    // ARRANGE
    const stack = getRoleTestStack();

    // ACT
    const template = Template.fromStack(stack);
    const roles = template.findResources('AWS::IAM::Role');
    const inlineStatements = Object.values(roles).flatMap((role) =>
      (
        (role.Properties.Policies ?? []) as Array<{ PolicyDocument: { Statement: Array<Record<string, unknown>> } }>
      ).flatMap((policy) => policy.PolicyDocument.Statement),
    );
    const managedPolicies = template.findResources('AWS::IAM::Policy');
    const managedStatements = Object.values(managedPolicies).flatMap(
      (policy) => policy.Properties.PolicyDocument.Statement as Array<Record<string, unknown>>,
    );
    const allStatements = [...inlineStatements, ...managedStatements];
    const statementsWithStepExecutions = allStatements.filter((statement) => {
      const action = statement.Action;
      return Array.isArray(action) && action.includes('ssm:DescribeAutomationStepExecutions');
    });

    // ASSERT
    // GetAutomationExecution + DescribeAutomationStepExecutions (both support
    // resource-level permissions) are scoped to automation-execution ARNs.
    expect(statementsWithStepExecutions).toHaveLength(1);
    const scopedStatement = statementsWithStepExecutions[0];
    expect(scopedStatement.Action).toEqual(['ssm:GetAutomationExecution', 'ssm:DescribeAutomationStepExecutions']);
    expect(scopedStatement.Resource).not.toBe('*');
    expect(JSON.stringify(scopedStatement.Resource)).toContain(':automation-execution/*');

    // DescribeAutomationExecutions (no resource-level support) stays on '*',
    // no longer bundled with the scopable actions.
    const describeAllStatement = allStatements.find(
      (statement) => statement.Action === 'ssm:DescribeAutomationExecutions',
    );
    expect(describeAllStatement).toBeDefined();
    expect(describeAllStatement?.Resource).toBe('*');
  });

  test('Orchestrator member role can reassert the boundary on an existing custom remediation role', () => {
    // ARRANGE
    const stack = getRoleTestStack();

    // ACT
    const template = Template.fromStack(stack);
    const roles = template.findResources('AWS::IAM::Role');
    const inlineStatements = Object.values(roles).flatMap((role) =>
      (
        (role.Properties.Policies ?? []) as Array<{ PolicyDocument: { Statement: Array<Record<string, unknown>> } }>
      ).flatMap((policy) => policy.PolicyDocument.Statement),
    );
    const managedStatements = Object.values(template.findResources('AWS::IAM::Policy')).flatMap(
      (policy) => policy.Properties.PolicyDocument.Statement as Array<Record<string, unknown>>,
    );
    const allStatements = [...inlineStatements, ...managedStatements];

    const customRemediationRoleArn = (statement: Record<string, unknown>): boolean =>
      JSON.stringify(statement.Resource ?? '').includes('SO0111-Remediate-Custom-*');

    // ASSERT — CrossAccountRoleService attaches the boundary with CreateRole for a NEW
    // role, but reasserts it with PutRolePermissionsBoundary when the role already exists
    // (a redeploy, a retry, or a role left by an earlier attempt). Without an Allow for
    // that action the whole deploy reports zero accounts installed, permanently: the role
    // exists, so the create path never runs again. Verified against a live deployment,
    // where a custom runbook for a control whose role predated the deploy could not be
    // released at all.
    const allowStatements = allStatements.filter(
      (statement) => statement.Effect === 'Allow' && customRemediationRoleArn(statement),
    );
    const allowedActions = allowStatements.flatMap((statement) =>
      Array.isArray(statement.Action) ? (statement.Action as string[]) : [statement.Action as string],
    );
    expect(allowedActions).toContain('iam:PutRolePermissionsBoundary');

    // The Deny guard still decides WHICH boundary may be set, so the Allow above widens
    // reachability rather than privilege. Losing this would turn the Allow into a
    // privilege-escalation primitive.
    const denyStatements = allStatements.filter(
      (statement) => statement.Effect === 'Deny' && customRemediationRoleArn(statement),
    );
    const requireBoundary = denyStatements.find(
      (statement) => statement.Sid === 'RequireBoundaryOnCustomRemediationRoles',
    );
    expect(requireBoundary).toBeDefined();
    expect(requireBoundary?.Action).toEqual(['iam:CreateRole', 'iam:PutRolePermissionsBoundary']);
    expect(JSON.stringify(requireBoundary?.Condition)).toContain('SO0111-ASR-Remediation-Boundary');

    // Requiring the boundary on the way IN is only half the guard: iam:PutRolePolicy and
    // iam:UpdateAssumeRolePolicy are safe on these roles solely because the boundary cannot
    // be taken off afterwards. Denying removal outright keeps that true even if a future
    // change broadens the Allow above.
    const denyBoundaryRemoval = denyStatements.find(
      (statement) => statement.Sid === 'DenyBoundaryRemovalOnCustomRemediationRoles',
    );
    expect(denyBoundaryRemoval).toBeDefined();
    // CloudFormation renders a single-action statement as a string rather than a list.
    expect(denyBoundaryRemoval?.Action).toBe('iam:DeleteRolePermissionsBoundary');
    // Unconditional on purpose: the delete API carries no iam:PermissionsBoundary key, so a
    // condition modelled on the statement above would not constrain it.
    expect(denyBoundaryRemoval?.Condition).toBeUndefined();

    // Nothing may grant boundary removal on this name space, which is what makes the
    // unconditional Deny a statement of intent rather than a behaviour change.
    expect(allowedActions).not.toContain('iam:DeleteRolePermissionsBoundary');
  });

  test('Remediation permissions boundary allows service actions but hard-denies escalation primitives', () => {
    const stack = getRoleTestStack();

    const template = Template.fromStack(stack);
    const managedPolicies = template.findResources('AWS::IAM::ManagedPolicy');
    const boundaryEntry = Object.values(managedPolicies).find(
      (policy) => policy.Properties.ManagedPolicyName === 'SO0111-ASR-Remediation-Boundary',
    );

    if (!boundaryEntry) throw new Error('SO0111-ASR-Remediation-Boundary managed policy not found in the stack');

    expect(boundaryEntry.Properties.Description).toMatch(/^[\x20-\x7E]*$/);

    const statements = boundaryEntry.Properties.PolicyDocument.Statement as Array<Record<string, unknown>>;

    const allowStatement = statements.find((statement) => statement.Effect === 'Allow');
    expect(allowStatement?.Action).toBe('*');
    expect(allowStatement?.Resource).toBe('*');

    const wholesaleDeny = statements.find(
      (statement) => statement.Effect === 'Deny' && Array.isArray(statement.Action),
    );
    expect(wholesaleDeny?.Action).toEqual(['sts:*', 'organizations:*']);
    expect(wholesaleDeny?.Resource).toBe('*');

    const iamDeny = statements.find((statement) => statement.Effect === 'Deny' && statement.Action === 'iam:*');
    expect(iamDeny?.Resource).toBe('*');
    expect(iamDeny?.Condition).toEqual({ StringNotEquals: { 'iam:PassedToService': 'ssm.amazonaws.com' } });
  });

  function getSsmTestStack(): Stack {
    const app = new App();
    return new RemediationRunbookStack(app, 'stack', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
      ssmdocs: 'remediation_runbooks',
      roleStack: getRoleTestStack(),
      parameters: {
        Namespace: 'myNamespace',
      },
    });
  }

  test('Regional Documents', () => {
    const stack = getSsmTestStack();
    const template = Template.fromStack(stack);

    const templateJSON = template.toJSON();
    omitWaitResourceHash(template, templateJSON);
    expect(templateJSON).toMatchSnapshot();
  });

  test('GuardDuty.IAMUser role scopes iam:GetPolicy to managed-policy ARNs', () => {
    // ARRANGE
    const app = new App();
    const roleStack = new MemberRolesStack(app, 'roles', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
    });
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

    // ACT
    const roleTemplate = Template.fromStack(roleStack);
    const policies = roleTemplate.findResources('AWS::IAM::Policy');
    const allStatements = Object.values(policies).flatMap(
      (policy) => policy.Properties.PolicyDocument.Statement as Array<Record<string, unknown>>,
    );
    const statementsWithGetPolicy = allStatements.filter((statement) => {
      const action = statement.Action;
      return action === 'iam:GetPolicy' || (Array.isArray(action) && action.includes('iam:GetPolicy'));
    });

    // ASSERT
    // iam:GetPolicy lives in exactly one statement, is not bundled with any
    // other action, and is scoped to managed-policy ARNs rather than '*'.
    expect(statementsWithGetPolicy).toHaveLength(1);
    const getPolicyStatement = statementsWithGetPolicy[0];
    expect(getPolicyStatement.Action).toBe('iam:GetPolicy');
    expect(getPolicyStatement.Resource).not.toBe('*');
    const renderedResource = JSON.stringify(getPolicyStatement.Resource);
    expect(renderedResource).toContain(':policy/*');
    expect(renderedResource).toContain(':iam::aws:policy/*');

    // The remaining unscopable list operations still share the Resource '*'
    // statement, without iam:GetPolicy.
    roleTemplate.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: ['iam:ListVirtualMFADevices', 'iam:ListPolicies'],
            Effect: 'Allow',
            Resource: '*',
          }),
        ]),
      },
    });

    // ssm:GetAutomationExecution supports resource scoping, so it is bounded to
    // automation-execution ARNs rather than '*'.
    const getAutomationStatement = allStatements.find((statement) => statement.Action === 'ssm:GetAutomationExecution');
    expect(getAutomationStatement).toBeDefined();
    expect(getAutomationStatement?.Resource).not.toBe('*');
    expect(JSON.stringify(getAutomationStatement?.Resource)).toContain(':automation-execution/*');
  });

  test('Inspector remediation role attaches a scoped managed policy instead of unconditioned PutRolePolicy', () => {
    // ARRANGE
    const app = new App();
    const roleStack = new MemberRolesStack(app, 'roles', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
    });
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

    // ACT
    const roleTemplate = Template.fromStack(roleStack);
    const policies = roleTemplate.findResources('AWS::IAM::Policy');
    // Scope to the Inspector remediation policy only — other remediation roles
    // legitimately hold iam:PutRolePolicy narrowly scoped to service-linked-role
    // paths (e.g. aws-service-role/*), which is not the escalation primitive.
    const inspectorPolicyEntry = Object.entries(policies).find(([logicalId]) =>
      logicalId.includes('InspectorInstanceVulnerability'),
    );
    expect(inspectorPolicyEntry).toBeDefined();
    const inspectorStatements = inspectorPolicyEntry![1].Properties.PolicyDocument.Statement as Array<
      Record<string, unknown>
    >;

    // ASSERT
    // The privilege-escalation primitive is gone: the Inspector role no longer
    // grants iam:PutRolePolicy at all.
    const putRolePolicyAllows = inspectorStatements.filter((statement) => {
      const action = statement.Action;
      const actions = Array.isArray(action) ? action : [action];
      return statement.Effect === 'Allow' && actions.includes('iam:PutRolePolicy');
    });
    expect(putRolePolicyAllows).toHaveLength(0);

    // The remediation instead attaches a RemediationConfigBucketAccess managed
    // policy, scoped by an iam:PolicyARN condition so no arbitrary (e.g. admin)
    // policy can be attached to any role. (A separate statement attaches
    // AmazonSSMManagedInstanceCore under its own condition; select the one bound
    // to the bucket-access policy specifically.)
    const scopedAttachStatement = inspectorStatements.find((statement) => {
      const action = statement.Action;
      const actions = Array.isArray(action) ? action : [action];
      const policyArnCondition = (statement.Condition as { ArnLike?: { 'iam:PolicyARN'?: unknown } } | undefined)
        ?.ArnLike?.['iam:PolicyARN'];
      return (
        statement.Effect === 'Allow' &&
        actions.includes('iam:AttachRolePolicy') &&
        JSON.stringify(policyArnCondition ?? '').includes(':policy/ASR-RemediationConfigBucketAccess')
      );
    });
    expect(scopedAttachStatement).toBeDefined();
    // The scoped attach applies to role/* (the instance role name is unknown at
    // deploy time) but is constrained to the bucket-access policy name.
    expect(JSON.stringify(scopedAttachStatement?.Resource)).toContain(':role/*');

    // This stack is deployed once per account while the policy it points at is
    // created per region, so the condition matches the region-suffixed names
    // rather than one exact ARN. The trailing wildcard must stay
    // bound to the solution-owned prefix.
    const policyArnPattern = JSON.stringify(
      (scopedAttachStatement?.Condition as { ArnLike: { 'iam:PolicyARN': unknown } }).ArnLike['iam:PolicyARN'],
    );
    expect(policyArnPattern).toContain(':policy/ASR-RemediationConfigBucketAccess-*');
  });
});

describe('createControlRunbook', () => {
  const NAMESPACE = 'my_namespace';
  const app = new App();
  const stack = new Stack(app, 'myStack');

  it('should insert script and namespace into the control runbook', () => {
    const ssmDoc = RunbookFactory.createControlRunbook(stack, 'controlRunbookTest', {
      securityStandard: 'SECTEST',
      securityStandardVersion: '1.2.3',
      controlId: 'TEST.1',
      ssmDocPath: 'test/test_data/',
      ssmDocFileName: 'tstest-runbook.yaml',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'solutionstest',
      solutionId: 'SO0111',
      scriptPath: 'remediation_runbooks/scripts',
      namespace: NAMESPACE,
    });

    const content = ssmDoc.content as any;
    expect(content.mainSteps[0].inputs.Script).not.toMatch(/%%SCRIPT=/);
    expect(content.parameters.AutomationAssumeRole.default).toEqual(`SO0111-MyIAMRole-${NAMESPACE}`);
  });
});

describe('createRemediationRunbook', () => {
  const NAMESPACE = 'my_namespace';
  const app = new App();
  const stack = new Stack(app, 'myStack');

  it('should insert script and namespace into the remediation runbook', () => {
    const ssmDoc = RunbookFactory.createRemediationRunbook(stack, 'controlRunbookTest', {
      ssmDocPath: 'test/test_data/',
      ssmDocName: 'tstest-runbook',
      ssmDocFileName: 'tstest-runbook.yaml',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'solutionstest',
      solutionId: 'SO0111',
      scriptPath: 'remediation_runbooks/scripts',
      namespace: NAMESPACE,
    });

    const content = ssmDoc.content as any;
    expect(content.mainSteps[0].inputs.Script).not.toMatch(/%%SCRIPT=/);
    expect(content.parameters.AutomationAssumeRole.default).toEqual(`SO0111-MyIAMRole-${NAMESPACE}`);
  });
});
