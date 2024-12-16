// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import NamespaceParam, { NAMESPACE_REGEX } from '../namespace-param';

function createNamespaceParamStack(): Stack {
  const app = new App();
  const stack = new Stack(app, 'NamespaceStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  });
  Aspects.of(stack).add(new AwsSolutionsChecks({ verbose: true }));
  new NamespaceParam(stack, 'NamespaceParam');
  return stack;
}

describe('namespace param stack', function () {
  const template = Template.fromStack(createNamespaceParamStack());

  it('matches snapshot', function () {
    expect(template).toMatchSnapshot();
  });

  describe('template param', function () {
    it('is present', function () {
      template.hasParameter('Namespace', {
        AllowedPattern: NAMESPACE_REGEX.source,
        Type: 'String',
      });
    });
  });
});

describe('namespace regex', function () {
  it('matches valid strings', function () {
    expect('my-test-n').toMatch(NAMESPACE_REGEX);
    expect('namespace').toMatch(NAMESPACE_REGEX);
    expect('123456789').toMatch(NAMESPACE_REGEX);
    expect('my2-e0lv').toMatch(NAMESPACE_REGEX);
  });

  it('does not match invalid strings', function () {
    expect('-test').not.toMatch(NAMESPACE_REGEX);
    expect('Namespace').not.toMatch(NAMESPACE_REGEX);
    expect('1234567890').not.toMatch(NAMESPACE_REGEX);
    expect('mY2-e0Lv').not.toMatch(NAMESPACE_REGEX);
    expect('nw').not.toMatch(NAMESPACE_REGEX);
    expect('sthree-nw').not.toMatch(NAMESPACE_REGEX);
    expect('xn--n').not.toMatch(NAMESPACE_REGEX);
    expect('nw-s3alias').not.toMatch(NAMESPACE_REGEX);
  });
});
