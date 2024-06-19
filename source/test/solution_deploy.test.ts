// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { SolutionDeployStack } from '../lib/solution_deploy-stack';
import { AppRegister } from '../lib/appregistry/applyAppRegistry';

function getTestStack(): Stack {
  const envEU = { account: '111111111111', region: 'eu-west-1' };
  const app = new App();
  const appName = 'automated-security-response-on-aws';
  const appregistry = new AppRegister({
    solutionId: 'SO0111',
    solutionName: appName,
    solutionVersion: 'v1.0.0',
    appRegistryApplicationName: appName,
    applicationType: 'AWS-Solutions',
  });
  const stack = new SolutionDeployStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    env: envEU,
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'solutions',
    solutionTMN: 'automated-security-response-on-aws',
    solutionName: 'AWS Security Hub Automated Response & Remediation',
    runtimePython: Runtime.PYTHON_3_9,
    orchLogGroup: 'ORCH_LOG_GROUP',
  });
  appregistry.applyAppRegistryToStacks(stack, stack.nestedStacksWithAppRegistry);
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

test('Test if the Stack has all the resources.', () => {
  process.env.DIST_OUTPUT_BUCKET = 'solutions';
  process.env.SOLUTION_NAME = 'AWS Security Hub Automated Response & Remediation';
  process.env.DIST_VERSION = 'v1.0.0';
  process.env.SOLUTION_ID = 'SO0111111';
  process.env.SOLUTION_TRADEMARKEDNAME = 'automated-security-response-on-aws';
  expect(Template.fromStack(getTestStack())).toMatchSnapshot();
});
