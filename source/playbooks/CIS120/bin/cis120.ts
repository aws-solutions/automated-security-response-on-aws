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
import { PlaybookPrimaryStack, PlaybookMemberStack, IControl } from '../../../lib/sharrplaybook-construct';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'CIS'
const standardLongName = 'cis-aws-foundations-benchmark'
const standardVersion = '1.2.0' // DO NOT INCLUDE 'V'

const app = new cdk.App();

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
let remediations: IControl[] = [
    { "control": "1.3" },
	{ "control": "1.4" },
    { "control": "1.5" },
	{ 
		"control": "1.6",
		"executes": "1.5"
	},
	{ 
		"control": "1.7",
		"executes": "1.5"
	},
	{ 
		"control": "1.8",
		"executes": "1.5" 
	},
	{ 
		"control": "1.9",
		"executes": "1.5"
	},
	{ 
		"control": "1.10",
		"executes": "1.5" 
	},
	{ 
		"control": "1.11",
		"executes": "1.5" 
	},
	// { "control": "1.20" },
    { "control": "2.1" },
    { "control": "2.2" },
    { "control": "2.3" },
    { "control": "2.4" },
	{ "control": "2.5" },
    { "control": "2.6" },
    { "control": "2.7" },
    { "control": "2.8" },
    { "control": "2.9" },
	{ "control": "3.1" },
	{ 
		"control": "3.2",
		"executes": "3.1" 
	},
	{ 
		"control": "3.3",
		"executes": "3.1" 
	},
	{ 
		"control": "3.4",
		"executes": "3.1" 
	},
	{ 
		"control": "3.5",
		"executes": "3.1" 
	},
	{ 
		"control": "3.6",
		"executes": "3.1" 
	},
	{ 
		"control": "3.7",
		"executes": "3.1" 
	},
	{ 
		"control": "3.8",
		"executes": "3.1" 
	},
	{ 
		"control": "3.9",
		"executes": "3.1" 
	},
	{ 
		"control": "3.10",
		"executes": "3.1" 
	},
	{ 
		"control": "3.11",
		"executes": "3.1" 
	},
	{ 
		"control": "3.12",
		"executes": "3.1" 
	},
	{ 
		"control": "3.13",
		"executes": "3.1" 
	},
	{ 
		"control": "3.14",
		"executes": "3.1" 
	},
    { "control": "4.1" },
	{ 
		"control": "4.2",
		"executes": "4.1" 
	},
    { "control": "4.3" }
	{ "control": "1.16" }
	{ "control": "1.20" }
	{ "control": "1.22" }
]

const adminStack = new PlaybookPrimaryStack(app, 'CIS120Stack', {
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

const memberStack = new PlaybookMemberStack(app, 'CIS120MemberStack', {
	description: `(${SOLUTION_ID}C) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Member Account, ${DIST_VERSION}`,
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
