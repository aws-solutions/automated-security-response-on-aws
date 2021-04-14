#!/usr/bin/env node
/*****************************************************************************
 *  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
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
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { AfsbpPrimaryStack } from '../lib/afsbp-primary-stack';
import { AfsbpMemberStack } from '../lib/afsbp-member-stack';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const app = new cdk.App();

const afsbpStack = new AfsbpPrimaryStack(app, 'AFSBPStack', {
	description: '(' + SOLUTION_ID + 'P) ' + SOLUTION_NAME +
		' AFSBP Compliance Pack - Admin Account, ' + DIST_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: DIST_VERSION,
	solutionName: SOLUTION_NAME,
	solutionDistBucket: DIST_OUTPUT_BUCKET,
	solutionDistName: DIST_SOLUTION_NAME
});

const afsbpMemberStack = new AfsbpMemberStack(app, 'AFSBPMemberStack', {
	description: '(' + SOLUTION_ID + 'M) ' + SOLUTION_NAME +
		' AFSBP Compliance Pack - Member Account, ' + DIST_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: DIST_VERSION,
	solutionName: SOLUTION_NAME,
	solutionDistBucket: DIST_OUTPUT_BUCKET,
	solutionDistName: DIST_SOLUTION_NAME,
	securityStandard: 'AFSBP'
});

afsbpStack.templateOptions.templateFormatVersion = "2010-09-09"
afsbpMemberStack.templateOptions.templateFormatVersion = "2010-09-09"
