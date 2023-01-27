// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AdminAccountParm } from '../lib/admin_account_parm-construct';

function createAdminAccountParm(): Stack {
  const app = new App();
  const stack = new Stack(app, 'testStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    stackName: 'testStack',
  });
  new AdminAccountParm(stack, 'roles');
  return stack;
}

test('AdminParm Test Stack', () => {
  expect(Template.fromStack(createAdminAccountParm())).toMatchSnapshot();
});
