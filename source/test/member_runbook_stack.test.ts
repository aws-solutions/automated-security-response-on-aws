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

    // The remediation instead attaches the fixed RemediationConfigBucketAccess
    // managed policy, scoped by an iam:PolicyARN condition so no arbitrary
    // (e.g. admin) policy can be attached to any role. (A separate statement
    // attaches AmazonSSMManagedInstanceCore under its own condition; select the
    // one bound to the bucket-access policy specifically.)
    const scopedAttachStatement = inspectorStatements.find((statement) => {
      const action = statement.Action;
      const actions = Array.isArray(action) ? action : [action];
      const policyArnCondition = (statement.Condition as { ArnEquals?: { 'iam:PolicyARN'?: unknown } } | undefined)
        ?.ArnEquals?.['iam:PolicyARN'];
      return (
        statement.Effect === 'Allow' &&
        actions.includes('iam:AttachRolePolicy') &&
        JSON.stringify(policyArnCondition ?? '').includes(':policy/ASR-RemediationConfigBucketAccess')
      );
    });
    expect(scopedAttachStatement).toBeDefined();
    // The scoped attach applies to role/* (the instance role name is unknown at
    // deploy time) but is constrained to exactly the bucket-access policy ARN.
    expect(JSON.stringify(scopedAttachStatement?.Resource)).toContain(':role/*');
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
