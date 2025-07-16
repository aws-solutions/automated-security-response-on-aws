#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { JiraBlueprintStack } from '../jira-blueprint-stack';
import { SolutionProps } from '../../../cdk/blueprint-stack';

const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'unknown';
const SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'] || 'unknown';
const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || 'unknown';
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_11;

// Blueprint function names
const JIRA_FUNCTION_NAME = SOLUTION_ID + '-ASR-Jira-TicketGenerator';

const app = new cdk.App();

const solutionProps: SolutionProps = {
  solutionId: SOLUTION_ID,
  solutionTMN: SOLUTION_TMN,
  solutionDistBucket: SOLUTION_BUCKET,
  solutionVersion: SOLUTION_VERSION,
  runtimePython: LAMBDA_RUNTIME_PYTHON,
};

const jiraBlueprintStack = new JiraBlueprintStack(app, 'JiraBlueprintStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: '(' + SOLUTION_ID + 'J) ' + SOLUTION_NAME + ' Jira Blueprint Stack, ' + SOLUTION_VERSION,
  solutionInfo: solutionProps,
  functionName: JIRA_FUNCTION_NAME,
  serviceName: 'Jira',
  requiredSecretKeys: ['Username', 'Password'],
  exampleUri: 'https://my-jira-instance.atlassian.net',
  uriPattern: String.raw`^https:\/\/.+\.atlassian\.net$`,
});
jiraBlueprintStack.templateOptions.templateFormatVersion = '2010-09-09';

// add metadata tags to all resources
cdk.Tags.of(app).add('Solutions:SolutionID', SOLUTION_ID);
cdk.Tags.of(app).add('Solutions:SolutionName', SOLUTION_TMN);
cdk.Tags.of(app).add('Solutions:SolutionVersion', SOLUTION_VERSION);
