#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { AdministratorStack } from '../../lib/administrator-stack';
import { OrchLogStack } from '../../lib/orchestrator-log-stack';
import { MemberRolesStack } from '../../lib/member-roles-stack';
import { MemberStack } from '../../lib/member-stack';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk from 'aws-cdk-lib';
import { RemediationRunbookStack } from '../../lib/remediation-runbook-stack';
import { MemberCloudTrailStack } from '../../lib/member/cloud-trail';

const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'unknown';
const SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'] || 'unknown';
const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || 'unknown';
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_11;

const app = new cdk.App();

let LOG_GROUP = `${SOLUTION_ID}-ASR-Orchestrator`;
LOG_GROUP = LOG_GROUP.replace(/^DEV-/, ''); // prefix on every resource name

const primarySolutionSNSTopicName = `${SOLUTION_ID}-ASR_Topic`;
const ACTION_LOG_LOGGROUP_NAME = '/aws/lambda/SO0111-ASR-CloudTrailEvents';

const solutionStack = new AdministratorStack(app, 'SolutionDeployStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: '(' + SOLUTION_ID + ') ' + SOLUTION_NAME + ' Administrator Stack, ' + SOLUTION_VERSION,
  solutionId: SOLUTION_ID,
  solutionVersion: SOLUTION_VERSION,
  solutionDistBucket: SOLUTION_BUCKET,
  solutionTMN: SOLUTION_TMN,
  solutionName: SOLUTION_NAME,
  runtimePython: LAMBDA_RUNTIME_PYTHON,
  orchestratorLogGroup: LOG_GROUP,
  SNSTopicName: primarySolutionSNSTopicName,
  cloudTrailLogGroupName: ACTION_LOG_LOGGROUP_NAME,
});
solutionStack.templateOptions.templateFormatVersion = '2010-09-09';

const memberStack = new MemberStack(app, 'MemberStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: '(' + SOLUTION_ID + 'M) ' + SOLUTION_NAME + ' Member Account Stack, ' + SOLUTION_VERSION,
  solutionId: SOLUTION_ID,
  solutionTradeMarkName: SOLUTION_TMN,
  solutionDistBucket: SOLUTION_BUCKET,
  solutionVersion: SOLUTION_VERSION,
  runtimePython: LAMBDA_RUNTIME_PYTHON,
  SNSTopicName: primarySolutionSNSTopicName,
  cloudTrailLogGroupName: ACTION_LOG_LOGGROUP_NAME,
});
memberStack.templateOptions.templateFormatVersion = '2010-09-09';

const roleStack = new MemberRolesStack(app, 'MemberRolesStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: '(' + SOLUTION_ID + 'R) ' + SOLUTION_NAME + ' Remediation Roles, ' + SOLUTION_VERSION,
  solutionId: SOLUTION_ID,
  solutionVersion: SOLUTION_VERSION,
  solutionDistBucket: SOLUTION_BUCKET,
});
roleStack.templateOptions.templateFormatVersion = '2010-09-09';

const runbookStack = new RemediationRunbookStack(app, 'RunbookStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: '(' + SOLUTION_ID + 'R) ' + SOLUTION_NAME + ' Remediation Runbooks, ' + SOLUTION_VERSION,
  solutionId: SOLUTION_ID,
  solutionVersion: SOLUTION_VERSION,
  solutionDistBucket: SOLUTION_BUCKET,
  roleStack: roleStack,
  parameters: {
    Namespace: roleStack.getNamespace(),
  },
});
runbookStack.templateOptions.templateFormatVersion = '2010-09-09';

const memberCloudTrailStack = new MemberCloudTrailStack(app, 'MemberCloudTrailStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description:
    '(' + SOLUTION_ID + 'CT) ' + SOLUTION_NAME + ' Cloud trail resources for Action Log feature, ' + SOLUTION_VERSION,
});
memberCloudTrailStack.templateOptions.templateFormatVersion = '2010-09-09';

const orchLogStack = new OrchLogStack(app, 'OrchestratorLogStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${SOLUTION_ID}L) ${SOLUTION_NAME} Orchestrator Log, ${SOLUTION_VERSION}`,
  logGroupName: LOG_GROUP,
  solutionId: SOLUTION_ID,
});
orchLogStack.templateOptions.templateFormatVersion = '2010-09-09';

// add metadata tags to all resources
cdk.Tags.of(app).add('Solutions:SolutionID', SOLUTION_ID);
cdk.Tags.of(app).add('Solutions:SolutionName', SOLUTION_TMN);
cdk.Tags.of(app).add('Solutions:SolutionVersion', SOLUTION_VERSION);
