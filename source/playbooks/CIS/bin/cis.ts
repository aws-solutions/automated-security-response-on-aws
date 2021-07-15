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
import { CisStack } from '../lib/cis-stack';
import { CisPermissionsStack } from '../lib/cis-permissions-stack';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const app = new cdk.App();

const cisStack = new CisStack(app, 'CISStack', {
	description: '(' + SOLUTION_ID + ') ' + SOLUTION_NAME +
		' CIS Compliance Pack, ' + DIST_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: DIST_VERSION,
	solutionName: SOLUTION_NAME,
	solutionDistBucket: DIST_OUTPUT_BUCKET,
	solutionDistName: DIST_SOLUTION_NAME
});

const cisPermStack = new CisPermissionsStack(app, 'CISPermissionsStack', {
	description: '(' + SOLUTION_ID + ') ' + SOLUTION_NAME +
		' CIS Compliance Pack Permissions, ' + DIST_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: DIST_VERSION,
	solutionName: SOLUTION_NAME,
	solutionDistBucket: DIST_OUTPUT_BUCKET,
	solutionDistName: DIST_SOLUTION_NAME
});

const stackMedata = {
	"AWS::CloudFormation::Interface": {
		"ParameterGroups": [
			{
				"Label": { "default": "Even if you do not enable fully automated remediation, you can still trigger a remediation action in the Security Hub console by selecting a specific finding, clicking the Action menu, and choosing the remediation action." },
				"Parameters": ["CIS1314AutoRemediation", "CIS15111AutoRemediation", "CIS116AutoRemediation", "CIS120AutoRemediation", "CIS22AutoRemediation", "CIS23AutoRemediation",
					"CIS24AutoRemediation", "CIS26AutoRemediation", "CIS27AutoRemediation", "CIS28AutoRemediation", "CIS29AutoRemediation",
					"CIS4142AutoRemediation", "CIS43AutoRemediation"]
			}
		],
	}
}

cisStack.templateOptions.metadata = stackMedata;

cisStack.templateOptions.templateFormatVersion = "2010-09-09"
cisPermStack.templateOptions.templateFormatVersion = "2010-09-09"
