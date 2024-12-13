#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk_nag from 'cdk-nag';
import * as cdk from 'aws-cdk-lib';
import { ServiceNowBlueprintStack } from '../servicenow-blueprint-stack';
import { SolutionProps } from '../../../cdk/blueprint-stack';

const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'unknown';
const SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'] || 'unknown';
const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || 'unknown';
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_11;

// Blueprint function names
const SERVICENOW_FUNCTION_NAME = SOLUTION_ID + '-ASR-ServiceNow-TicketGenerator';

const app = new cdk.App();
cdk.Aspects.of(app).add(new cdk_nag.AwsSolutionsChecks({ verbose: true }));

const solutionProps: SolutionProps = {
  solutionId: SOLUTION_ID,
  solutionTMN: SOLUTION_TMN,
  solutionDistBucket: SOLUTION_BUCKET,
  solutionVersion: SOLUTION_VERSION,
  runtimePython: LAMBDA_RUNTIME_PYTHON,
};

const serviceNowBlueprintStack = new ServiceNowBlueprintStack(app, 'ServiceNowBlueprintStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: '(' + SOLUTION_ID + 'J) ' + SOLUTION_NAME + ' ServiceNow Blueprint Stack, ' + SOLUTION_VERSION,
  solutionInfo: solutionProps,
  functionName: SERVICENOW_FUNCTION_NAME,
  serviceName: 'ServiceNow',
  requiredSecretKeys: ['API_Key'],
  exampleUri: 'https://my-servicenow-instance.service-now.com',
  uriPattern: String.raw`^https:\/\/.+\.service-now\.com`,
});
serviceNowBlueprintStack.templateOptions.templateFormatVersion = '2010-09-09';

// ========== CDK Nag Suppressions ============

cdk_nag.NagSuppressions.addResourceSuppressionsByPath(
  serviceNowBlueprintStack,
  '/ServiceNowBlueprintStack/TicketGeneratorRole-ServiceNow/DefaultPolicy/Resource',
  [
    {
      id: 'AwsSolutions-IAM5',
      reason: 'Resource * is required to enable x-ray tracing.',
      appliesTo: ['Resource::*'],
    },
  ],
);
cdk_nag.NagSuppressions.addStackSuppressions(
  serviceNowBlueprintStack,
  [
    {
      id: 'AwsSolutions-L1',
      reason: 'Python 3.12 runtime not yet available in GovCloud/China regions',
    },
  ],
  true,
);
