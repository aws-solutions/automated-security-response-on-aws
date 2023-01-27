// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MemberStack } from '../solution_deploy/lib/member-stack';

function getCatStack(): Stack {
  const app = new App();
  const stack = new MemberStack(app, 'CatalogStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation',
    runtimePython: Runtime.PYTHON_3_9,
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

test('default stack', () => {
  expect(Template.fromStack(getCatStack())).toMatchSnapshot();
});
