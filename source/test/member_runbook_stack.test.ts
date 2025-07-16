// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { RunbookFactory } from '../lib/runbook_factory';
import { omitWaitResourceHash } from './utils';
import { RemediationRunbookStack } from '../lib/remediation-runbook-stack';

describe('MemberRolesStack tests', () => {
  function getRoleTestStack(): MemberRolesStack {
    const app = new App();
    const stack = new MemberRolesStack(app, 'roles', {
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: 'test;',
      solutionId: 'SO0111',
      solutionVersion: 'v1.1.1',
      solutionDistBucket: 'sharrbukkit',
    });
    return stack;
  }
  test('Global Roles Stack', () => {
    const stack = getRoleTestStack();
    const template = Template.fromStack(stack);

    const templateJSON = template.toJSON();
    omitWaitResourceHash(template, templateJSON);
    expect(templateJSON).toMatchSnapshot();
  });

  function getSsmTestStack(): Stack {
    const app = new App();
    const stack = new RemediationRunbookStack(app, 'stack', {
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
    return stack;
  }

  test('Regional Documents', () => {
    const stack = getSsmTestStack();
    const template = Template.fromStack(stack);

    const templateJSON = template.toJSON();
    omitWaitResourceHash(template, templateJSON);
    expect(templateJSON).toMatchSnapshot();
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
    expect(content.mainSteps[1].inputs.Script).not.toMatch(/%%SCRIPT=/);
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
    expect(content.mainSteps[1].inputs.Script).not.toMatch(/%%SCRIPT=/);
    expect(content.parameters.AutomationAssumeRole.default).toEqual(`SO0111-MyIAMRole-${NAMESPACE}`);
  });
});
