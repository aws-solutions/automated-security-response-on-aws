#!/usr/bin/env node
/*****************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/

import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import { SolutionDeployStack } from '../lib/solution_deploy-stack';
import { MemberStack } from '../lib/sharr_member-stack';
import { RemediationRunbookStack } from '../lib/remediation_runbook-stack';
import { OrchLogStack } from '../lib/orchestrator-log-stack';

const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'unknown';
const SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'] || 'unknown';
const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || 'unknown';
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_8

const app = new cdk.App();

let LOG_GROUP = `${SOLUTION_ID}-SHARR-Orchestrator`
LOG_GROUP = LOG_GROUP.replace(/^DEV-/,''); // prefix on every resource name

const solStack = new SolutionDeployStack(app, 'SolutionDeployStack', {
	description: '(' + SOLUTION_ID + ') ' + SOLUTION_NAME + ' Administrator Stack, ' + SOLUTION_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: SOLUTION_VERSION,
    solutionDistBucket: SOLUTION_BUCKET,
    solutionTMN: SOLUTION_TMN,
    solutionName: SOLUTION_NAME,
    runtimePython: LAMBDA_RUNTIME_PYTHON,
    orchLogGroup: LOG_GROUP
});
solStack.templateOptions.templateFormatVersion = "2010-09-09"

const memberStack = new MemberStack(app, 'MemberStack', {
    description: '(' + SOLUTION_ID + 'M) ' + SOLUTION_NAME + ' Member Account Stack, ' + SOLUTION_VERSION,
    solutionId: SOLUTION_ID,
    solutionTMN: SOLUTION_TMN,
    solutionDistBucket: SOLUTION_BUCKET,
    solutionVersion: SOLUTION_VERSION
});
memberStack.templateOptions.templateFormatVersion = "2010-09-09"

const runbookStack = new RemediationRunbookStack(app, 'RunbookStack', {
    description: '(' + SOLUTION_ID + 'R) ' + SOLUTION_NAME +
        ' Remediation Runbooks, ' + SOLUTION_VERSION,
    solutionId: SOLUTION_ID,
    solutionVersion: SOLUTION_VERSION,
    solutionDistBucket: SOLUTION_BUCKET,
});
runbookStack.templateOptions.templateFormatVersion = "2010-09-09"

const orchLogStack = new OrchLogStack(app, 'OrchestratorLogStack', {
    description: `(${SOLUTION_ID}L) ${SOLUTION_NAME} Orchestrator Log, ${SOLUTION_VERSION}`,
    logGroupName: LOG_GROUP,
    solutionId: SOLUTION_ID
});
orchLogStack.templateOptions.templateFormatVersion = "2010-09-09"
