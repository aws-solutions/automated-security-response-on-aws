// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AdminAccountParm } from './admin_account_parm-construct';

function createAdminAccountParameterStack(): Stack {
  const app = new App();
  const stack = new Stack(app, 'AdminAccountParameterStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });
  Aspects.of(stack).add(new AwsSolutionsChecks({ verbose: true }));
  new AdminAccountParm(stack, 'AdminAccountParameter');
  return stack;
}

test('AdminParm Test Stack', () => {
  expect(Template.fromStack(createAdminAccountParameterStack())).toMatchSnapshot();
});
