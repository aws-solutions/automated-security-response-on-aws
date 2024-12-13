#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { AdministratorStack } from '../../lib/administrator-stack';
import { OrchLogStack } from '../../lib/orchestrator-log-stack';
import { RemediationRunbookStack, MemberRoleStack } from '../../lib/remediation_runbook-stack';
import { MemberStack } from '../../lib/member-stack';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cdk_nag from 'cdk-nag';
import * as cdk from 'aws-cdk-lib';
import { AppRegister } from '../../lib/appregistry/applyAppRegistry';

const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'unknown';
const SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'] || 'unknown';
const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || 'unknown';
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_11;

const app = new cdk.App();
cdk.Aspects.of(app).add(new cdk_nag.AwsSolutionsChecks({ verbose: true }));

let LOG_GROUP = `${SOLUTION_ID}-SHARR-Orchestrator`;
LOG_GROUP = LOG_GROUP.replace(/^DEV-/, ''); // prefix on every resource name

const primarySolutionSNSTopicName = `${SOLUTION_ID}-SHARR_Topic`;
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

const roleStack = new MemberRoleStack(app, 'MemberRoleStack', {
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

const orchLogStack = new OrchLogStack(app, 'OrchestratorLogStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${SOLUTION_ID}L) ${SOLUTION_NAME} Orchestrator Log, ${SOLUTION_VERSION}`,
  logGroupName: LOG_GROUP,
  solutionId: SOLUTION_ID,
});
orchLogStack.templateOptions.templateFormatVersion = '2010-09-09';

const appName = 'automated-security-response-on-aws';
const appregistry = new AppRegister({
  solutionId: SOLUTION_ID,
  solutionName: appName,
  solutionVersion: SOLUTION_VERSION,
  appRegistryApplicationName: appName,
  applicationType: 'AWS-Solutions',
});

// Do not associate spoke stacks, we must allow other regions
appregistry.applyAppRegistry(
  solutionStack,
  solutionStack.nestedStacksWithAppRegistry,
  solutionStack.getPrimarySolutionSNSTopicARN(),
);
appregistry.applyAppRegistry(
  memberStack,
  memberStack.nestedStacksWithAppRegistry,
  memberStack.getPrimarySolutionSNSTopicARN(),
);

// ========== CDK Nag Suppressions ============

cdk_nag.NagSuppressions.addResourceSuppressionsByPath(
  solutionStack,
  '/SolutionDeployStack/notifyRole/DefaultPolicy/Resource',
  [
    {
      id: 'AwsSolutions-IAM5',
      reason: 'Resource * is required to enable x-ray tracing.',
      appliesTo: ['Resource::*'],
    },
  ],
);
cdk_nag.NagSuppressions.addResourceSuppressionsByPath(
  solutionStack,
  '/SolutionDeployStack/SchedulingLambdaRole/DefaultPolicy/Resource',
  [
    {
      id: 'AwsSolutions-IAM5',
      reason: 'Resource * is required to enable x-ray tracing.',
      appliesTo: ['Resource::*'],
    },
  ],
);

cdk_nag.NagSuppressions.addResourceSuppressionsByPath(
  solutionStack,
  '/SolutionDeployStack/orchestratorRole/DefaultPolicy/Resource',
  [
    {
      id: 'AwsSolutions-IAM5',
      reason: 'Resource * is required to enable x-ray tracing.',
      appliesTo: ['Resource::*'],
    },
  ],
);

cdk_nag.NagSuppressions.addResourceSuppressionsByPath(
  memberStack,
  '/MemberStack/MemberCloudTrail/S3TriggerRole/DefaultPolicy/Resource',
  [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'The S3TriggerRole requires wildcard permissions on the ActionLogSHARREventProcessor Lambda function to allow the S3 bucket in the member accounts to invoke the Lambda function.',
    },
  ],
);

cdk_nag.NagSuppressions.addStackSuppressions(roleStack, [
  {
    id: 'AwsSolutions-IAM5',
    reason: 'Resource and action wildcards are needed to remediate findings on arbitrary resources',
  },
]);

cdk_nag.NagSuppressions.addStackSuppressions(
  solutionStack,
  [
    {
      id: 'AwsSolutions-L1',
      reason: 'Python 3.12 runtime not yet available in GovCloud/China regions',
    },
  ],
  true,
);

cdk_nag.NagSuppressions.addStackSuppressions(
  memberStack,
  [
    {
      id: 'AwsSolutions-L1',
      reason: 'Python 3.12 runtime not yet available in GovCloud/China regions',
    },
  ],
  true,
);
