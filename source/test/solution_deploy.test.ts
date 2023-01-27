// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { SolutionDeployStack } from '../solution_deploy/lib/solution_deploy-stack';

function getTestStack(): Stack {
  const envEU = { account: '111111111111', region: 'eu-west-1' };
  const app = new App();
  const stack = new SolutionDeployStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    env: envEU,
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'solutions',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation',
    solutionName: 'AWS Security Hub Automated Response & Remediation',
    runtimePython: Runtime.PYTHON_3_9,
    orchLogGroup: 'ORCH_LOG_GROUP',
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

test('Test if the Stack has all the resources.', () => {
  process.env.DIST_OUTPUT_BUCKET = 'solutions';
  process.env.SOLUTION_NAME = 'AWS Security Hub Automated Response & Remediation';
  process.env.DIST_VERSION = 'v1.0.0';
  process.env.SOLUTION_ID = 'SO0111111';
  process.env.SOLUTION_TRADEMARKEDNAME = 'aws-security-hub-automated-response-and-remediation';
  expect(Template.fromStack(getTestStack())).toMatchSnapshot();
});
