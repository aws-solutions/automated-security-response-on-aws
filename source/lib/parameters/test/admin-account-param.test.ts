// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import AdminAccountParam from '../admin-account-param';

function createAdminAccountParamStack(): Stack {
  const app = new App();
  const stack = new Stack(app, 'AdminAccountParamStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });
  Aspects.of(stack).add(new AwsSolutionsChecks({ verbose: true }));
  new AdminAccountParam(stack, 'AdminAccountParam');
  return stack;
}

describe('admin account param stack', function () {
  const template = Template.fromStack(createAdminAccountParamStack());

  it('matches snapshot', function () {
    expect(template).toMatchSnapshot();
  });

  describe('template param', function () {
    const allowedPattern = /^\d{12}$/;

    it('is present', function () {
      template.hasParameter('SecHubAdminAccount', {
        AllowedPattern: allowedPattern.source,
        Type: 'String',
      });
    });

    describe('allowed pattern', function () {
      it('matches account number', function () {
        expect('1'.repeat(12)).toMatch(allowedPattern);
      });

      it('does not match too long account number', function () {
        expect('1'.repeat(13)).not.toMatch(allowedPattern);
      });

      it('does not match words', function () {
        expect('MyAdminAccnt').not.toMatch(allowedPattern);
      });
    });
  });
});
