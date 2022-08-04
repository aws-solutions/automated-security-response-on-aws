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

import { SynthUtils } from '@aws-cdk/assert';
import * as lambda from '@aws-cdk/aws-lambda';
import * as cdk from '@aws-cdk/core';
import { MemberStack } from '../solution_deploy/lib/sharr_member-stack';
import { AwsSolutionsChecks } from 'cdk-nag'
import { Aspects } from '@aws-cdk/core'

function getCatStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new MemberStack(app, 'CatalogStack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionTMN: 'aws-security-hub-automated-response-and-remediation',
    runtimePython: lambda.Runtime.PYTHON_3_8
  });
  Aspects.of(app).add(new AwsSolutionsChecks({verbose: true}))
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getCatStack())).toMatchSnapshot();
});


