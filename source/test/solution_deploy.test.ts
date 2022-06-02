/*****************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/

import { expect as expectCDK, matchTemplate, MatchStyle, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import * as SolutionDeploy from '../solution_deploy/lib/solution_deploy-stack';
import { AwsSolutionsChecks } from 'cdk-nag'
import { Aspects } from '@aws-cdk/core'

function getTestStack(): cdk.Stack {
  const envEU = { account: '111111111111', region: 'eu-west-1' };
  const app = new cdk.App();
  const stack = new SolutionDeploy.SolutionDeployStack(app, 'stack', { 
    env: envEU,
    solutionId: 'SO0111',
    solutionVersion: 'v1.0.0',
    solutionDistBucket: 'solutions',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation',
    solutionName: 'AWS Security Hub Automated Response & Remediation',
    runtimePython: lambda.Runtime.PYTHON_3_8,
    orchLogGroup: 'ORCH_LOG_GROUP'
    
  })
  Aspects.of(app).add(new AwsSolutionsChecks({verbose: true}))
  return stack;
}

test('Test if the Stack has all the resources.', () => {
  process.env.DIST_OUTPUT_BUCKET = 'solutions'
  process.env.SOLUTION_NAME = 'AWS Security Hub Automated Response & Remediation'
  process.env.DIST_VERSION = 'v1.0.0'
  process.env.SOLUTION_ID = 'SO0111111'
  process.env.SOLUTION_TRADEMARKEDNAME = 'aws-security-hub-automated-response-and-remediation'
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});
