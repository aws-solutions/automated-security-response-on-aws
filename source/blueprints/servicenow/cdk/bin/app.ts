#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { ServiceNowBlueprintStack } from '../servicenow-blueprint-stack';
import { SolutionProps } from '../../../cdk/blueprint-stack';
import { getConfig, applyDynamicTags } from '../../../../lib/config/cdk-config';

const config = getConfig();
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_11;

// Blueprint function names
const SERVICENOW_FUNCTION_NAME = config.solution.id + '-ASR-ServiceNow-TicketGenerator';

const app = new cdk.App();
const solutionProps: SolutionProps = {
  solutionId: config.solution.id,
  solutionTMN: config.solution.trademarkedName,
  solutionDistBucket: config.build.distOutputBucket,
  solutionVersion: config.build.distVersion,
  runtimePython: LAMBDA_RUNTIME_PYTHON,
};

const serviceNowBlueprintStack = new ServiceNowBlueprintStack(app, 'ServiceNowBlueprintStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description:
    '(' +
    config.solution.id +
    'J) ' +
    config.solution.name +
    ' ServiceNow Blueprint Stack, ' +
    config.build.distVersion,
  solutionInfo: solutionProps,
  functionName: SERVICENOW_FUNCTION_NAME,
  serviceName: 'ServiceNow',
  requiredSecretKeys: ['API_Key'],
  exampleUri: 'https://my-servicenow-instance.service-now.com',
  uriPattern: String.raw`^https:\/\/.+\.service-now\.com`,
});
serviceNowBlueprintStack.templateOptions.templateFormatVersion = '2010-09-09';

// add metadata tags to all resources
cdk.Tags.of(app).add('Solutions:SolutionID', config.solution.id);
cdk.Tags.of(app).add('Solutions:SolutionName', config.solution.trademarkedName);
cdk.Tags.of(app).add('Solutions:SolutionVersion', config.build.distVersion);

applyDynamicTags(app);
