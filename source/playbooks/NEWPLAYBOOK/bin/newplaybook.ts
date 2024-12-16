#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { PlaybookPrimaryStack, PlaybookMemberStack, IControl } from '../../../lib/sharrplaybook-construct';
import * as cdk from 'aws-cdk-lib';
import * as cdk_nag from 'cdk-nag';
import 'source-map-support/register';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'NPB';
const standardLongName = 'NewPlaybook';
const standardVersion = '1.1.1'; // DO NOT INCLUDE 'V'

const app = new cdk.App();
cdk.Aspects.of(app).add(new cdk_nag.AwsSolutionsChecks());

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
const remediations: IControl[] = [{ control: 'RDS.6', versionAdded: '2.1.0' }];

const adminStack = new PlaybookPrimaryStack(app, 'NPBStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${SOLUTION_ID}P) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${DIST_VERSION}`,
  solutionId: SOLUTION_ID,
  solutionVersion: DIST_VERSION,
  solutionDistBucket: DIST_OUTPUT_BUCKET,
  solutionDistName: DIST_SOLUTION_NAME,
  remediations: remediations,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});

const memberStack = new PlaybookMemberStack(app, 'NPBMemberStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${SOLUTION_ID}M) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Member Account, ${DIST_VERSION}`,
  solutionId: SOLUTION_ID,
  solutionVersion: DIST_VERSION,
  solutionDistBucket: DIST_OUTPUT_BUCKET,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
  securityStandardLongName: standardLongName,
  remediations: remediations,
});

adminStack.templateOptions.templateFormatVersion = '2010-09-09';
memberStack.templateOptions.templateFormatVersion = '2010-09-09';
