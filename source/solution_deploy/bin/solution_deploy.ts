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

import * as cdk from '@aws-cdk/core';
import * as lambda from '@aws-cdk/aws-lambda';
import { SolutionDeployStack } from '../lib/solution_deploy-stack';
import { ServiceCatalogStack } from '../lib/service_catalog-stack';

const SOLUTION_ID = process.env['SOLUTION_ID'] || 'unknown';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'unknown';
const SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'] || 'unknown';
const SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || 'unknown';
const LAMBDA_RUNTIME_PYTHON = lambda.Runtime.PYTHON_3_8

const app = new cdk.App();

const solStack = new SolutionDeployStack(app, 'SolutionDeployStack', {
	description: '(' + SOLUTION_ID + ') ' + SOLUTION_NAME + ' Administrator Stack, ' + SOLUTION_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: SOLUTION_VERSION,
    solutionDistBucket: SOLUTION_BUCKET,
    solutionTMN: SOLUTION_TMN,
    solutionName: SOLUTION_NAME,
    runtimePython: LAMBDA_RUNTIME_PYTHON
});

const catStack = new ServiceCatalogStack(app, 'ServiceCatalogStack', {
	description: '(' + SOLUTION_ID + ') ' + SOLUTION_NAME + ' Service Catalog Stack, ' + SOLUTION_VERSION,
	solutionId: SOLUTION_ID,
	solutionVersion: SOLUTION_VERSION,
    solutionDistBucket: SOLUTION_BUCKET,
    solutionTMN: SOLUTION_TMN,
    solutionName: SOLUTION_NAME
});

solStack.templateOptions.templateFormatVersion = "2010-09-09"
catStack.templateOptions.templateFormatVersion = "2010-09-09"
