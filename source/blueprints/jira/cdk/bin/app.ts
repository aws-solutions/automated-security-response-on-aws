#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { JiraBlueprintStack } from '../jira-blueprint-stack';
import { SolutionProps } from '../../../cdk/blueprint-stack';
import { getConfig, applyDynamicTags } from '../../../../lib/config/cdk-config';

const config = getConfig();
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_11;

// Blueprint function names
const JIRA_FUNCTION_NAME = config.solution.id + '-ASR-Jira-TicketGenerator';

const app = new cdk.App();

const solutionProps: SolutionProps = {
  solutionId: config.solution.id,
  solutionTMN: config.solution.trademarkedName,
  solutionDistBucket: config.build.distOutputBucket,
  solutionVersion: config.build.distVersion,
  runtimePython: LAMBDA_RUNTIME_PYTHON,
};

const jiraBlueprintStack = new JiraBlueprintStack(app, 'JiraBlueprintStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description:
    '(' + config.solution.id + 'J) ' + config.solution.name + ' Jira Blueprint Stack, ' + config.build.distVersion,
  solutionInfo: solutionProps,
  functionName: JIRA_FUNCTION_NAME,
  serviceName: 'Jira',
  requiredSecretKeys: ['Username', 'Password'],
  exampleUri: 'https://my-jira-instance.atlassian.net',
  uriPattern: String.raw`^https:\/\/.+\.atlassian\.net`,
});
jiraBlueprintStack.templateOptions.templateFormatVersion = '2010-09-09';

// add metadata tags to all resources
cdk.Tags.of(app).add('Solutions:SolutionID', config.solution.id);
cdk.Tags.of(app).add('Solutions:SolutionName', config.solution.trademarkedName);
cdk.Tags.of(app).add('Solutions:SolutionVersion', config.build.distVersion);

applyDynamicTags(app);
