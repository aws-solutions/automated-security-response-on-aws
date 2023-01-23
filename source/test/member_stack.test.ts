// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { SynthUtils } from '@aws-cdk/assert';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { MemberStack } from '../solution_deploy/lib/sharr_member-stack';
import { AwsSolutionsChecks } from 'cdk-nag';
import { Aspects } from 'aws-cdk-lib';

function getCatStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new MemberStack(app, 'CatalogStack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation',
    runtimePython: lambda.Runtime.PYTHON_3_9,
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getCatStack())).toMatchSnapshot();
});
