// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { SynthUtils } from '@aws-cdk/assert';
import '@aws-cdk/assert/jest';
import { App, Stack } from 'aws-cdk-lib';
import { AdminAccountParm } from '../lib/admin_account_parm-construct';

function createAdminAccountParm(): Stack {
  const app = new App();
  const stack = new Stack(app, 'testStack', {
    stackName: 'testStack',
  });
  new AdminAccountParm(stack, 'roles');
  return stack;
}

test('AdminParm Test Stack', () => {
  expect(SynthUtils.toCloudFormation(createAdminAccountParm())).toMatchSnapshot();
});
