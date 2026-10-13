// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { CfnScalableTarget } from 'aws-cdk-lib/aws-applicationautoscaling';
import { applyDynamicTags, getConfig, stripDevelopmentPrefix } from './cdk-config';

describe('stripDevelopmentPrefix', function () {
  it('strips a leading DEV- and leaves every other id untouched', function () {
    // ACT / ASSERT
    expect(stripDevelopmentPrefix('DEV-SO0111')).toEqual('SO0111');
    expect(stripDevelopmentPrefix('SO0111')).toEqual('SO0111');

    // Only a leading occurrence is a build prefix.
    expect(stripDevelopmentPrefix('SO0111-DEV-suffix')).toEqual('SO0111-DEV-suffix');

    // One call removes one leading segment, so a doubled prefix keeps the second.
    expect(stripDevelopmentPrefix('DEV-DEV-SO0111')).toEqual('DEV-SO0111');
  });
});

describe('getConfig resourceNamePrefix', function () {
  const originalSolutionId = process.env.SOLUTION_ID;

  afterEach(function () {
    if (originalSolutionId === undefined) {
      delete process.env.SOLUTION_ID;
    } else {
      process.env.SOLUTION_ID = originalSolutionId;
    }
    jest.resetModules();
  });

  it.each([
    ['DEV-SO0111', 'DEV-SO0111', 'SO0111'],
    ['SO0111', 'SO0111', 'SO0111'],
  ])('derives the prefix from SOLUTION_ID=%s', function (solutionId, expectedId, expectedPrefix) {
    // ARRANGE
    jest.resetModules();
    process.env.SOLUTION_ID = solutionId;

    // ACT
    // Re-require so the module-level config cache is rebuilt under this SOLUTION_ID.
    const config = jest.requireActual<typeof import('./cdk-config')>('./cdk-config').getConfig();

    // ASSERT
    expect(config.solution.id).toEqual(expectedId);
    expect(config.solution.resourceNamePrefix).toEqual(expectedPrefix);
  });

  it('never leaves a DEV- prefix on the derived value', function () {
    // ACT
    const config = getConfig();

    // ASSERT
    expect(config.solution.resourceNamePrefix).not.toMatch(/^DEV-/);
  });
});

describe('applyDynamicTags', function () {
  const originalDynamicTags = process.env.DYNAMIC_TAGS;

  afterEach(function () {
    if (originalDynamicTags === undefined) {
      delete process.env.DYNAMIC_TAGS;
    } else {
      process.env.DYNAMIC_TAGS = originalDynamicTags;
    }
  });

  it('skips ScalableTarget, which aws-us-gov rejects when tagged', function () {
    // ARRANGE
    process.env.DYNAMIC_TAGS = 'auto-delete=never';
    const app = new App();
    const stack = new Stack(app, 'DynamicTagsStack');
    new CfnScalableTarget(stack, 'ScalableTarget', {
      maxCapacity: 10,
      minCapacity: 1,
      resourceId: 'table/example',
      scalableDimension: 'dynamodb:table:ReadCapacityUnits',
      serviceNamespace: 'dynamodb',
    });

    // ACT
    applyDynamicTags(app);

    // ASSERT
    const scalableTargets = Template.fromStack(stack).findResources('AWS::ApplicationAutoScaling::ScalableTarget');
    expect(Object.values(scalableTargets).map((resource) => resource.Properties.Tags)).toEqual([undefined]);
  });
});
