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
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import {  PlaybookPrimaryStack, PlaybookMemberStack, IControl } from '../../../lib/sharrplaybook-construct';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'NPB'
const standardLongName = 'New Playbook'
const standardVersion = '1.1.1' // DO NOT INCLUDE 'V'

const app = new cdk.App();

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
const remediations: IControl[] = [
    { "control": "RDS.6" }
]

const adminStack = new PlaybookPrimaryStack(app, 'NPBStack', {
	description: `(${SOLUTION_ID}P) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${DIST_VERSION}`,
	solutionId: SOLUTION_ID,
	solutionVersion: DIST_VERSION,
	solutionDistBucket: DIST_OUTPUT_BUCKET,
	solutionDistName: DIST_SOLUTION_NAME,
	remediations: remediations,
	securityStandardLongName: standardLongName,
	securityStandard: standardShortName,
	securityStandardVersion: standardVersion
});

const memberStack = new PlaybookMemberStack(app, 'NPBMemberStack', {
	description: `(${SOLUTION_ID}M) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Member Account, ${DIST_VERSION}`,
	solutionId: SOLUTION_ID,
	solutionVersion: DIST_VERSION,
	solutionDistBucket: DIST_OUTPUT_BUCKET,
	securityStandard: standardShortName,
	securityStandardVersion: standardVersion,
	securityStandardLongName: standardLongName,
	remediations: remediations
});

adminStack.templateOptions.templateFormatVersion = "2010-09-09"
memberStack.templateOptions.templateFormatVersion = "2010-09-09"
