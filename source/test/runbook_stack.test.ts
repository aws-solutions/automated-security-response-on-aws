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
import * as cdk from '@aws-cdk/core';
import { MemberRoleStack, RemediationRunbookStack } from '../solution_deploy/lib/remediation_runbook-stack';
import { AwsSolutionsChecks } from 'cdk-nag'
import { Aspects } from '@aws-cdk/core'

const app = new cdk.App();

function getRoleTestStack(): MemberRoleStack {
  const app = new cdk.App();
  const stack = new MemberRoleStack(app, 'roles', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit'
  })
  return stack;
}
test('Global Roles Stack', () => {
  expect(SynthUtils.toCloudFormation(getRoleTestStack())).toMatchSnapshot();
});

function getSsmTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new RemediationRunbookStack(app, 'stack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'remediation_runbooks',
    roleStack: getRoleTestStack()
  })
  Aspects.of(app).add(new AwsSolutionsChecks({verbose: true}))
  return stack;
}

test('Regional Documents', () => {
  expect(SynthUtils.toCloudFormation(getSsmTestStack())).toMatchSnapshot();
});