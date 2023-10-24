#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { PlaybookPrimaryStack, IControl } from '../../../lib/sharrplaybook-construct';
import * as cdk_nag from 'cdk-nag';
import * as cdk from 'aws-cdk-lib';
import 'source-map-support/register';
import { CIS140PlaybookMemberStack } from '../lib/cis140_playbook-construct';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'CIS';
const standardLongName = 'cis-aws-foundations-benchmark';
const standardVersion = '1.4.0'; // DO NOT INCLUDE 'V'

const app = new cdk.App();
cdk.Aspects.of(app).add(new cdk_nag.AwsSolutionsChecks());

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
const remediations: IControl[] = [
  { control: '1.8' },
  { control: '1.9', executes: '1.8' },
  { control: '1.12' },
  { control: '1.14' },
  { control: '1.17' },
  { control: '2.1.1' },
  { control: '2.1.2' },
  { control: '2.1.5.1' }, //NOSONAR This is not an IP Address.
  { control: '2.1.5.2' }, //NOSONAR This is not an IP Address.
  { control: '2.2.1' },
  { control: '3.1' },
  { control: '3.2' },
  { control: '3.3' },
  { control: '3.4' },
  { control: '3.5' },
  { control: '3.6' },
  { control: '3.7' },
  { control: '3.8' },
  { control: '3.9' },
  { control: '4.1' },
  { control: '4.2', executes: '4.1' },
  { control: '4.3', executes: '4.1' },
  { control: '4.4', executes: '4.1' },
  { control: '4.5', executes: '4.1' },
  { control: '4.6', executes: '4.1' },
  { control: '4.7', executes: '4.1' },
  { control: '4.8', executes: '4.1' },
  { control: '4.9', executes: '4.1' },
  { control: '4.10', executes: '4.1' },
  { control: '4.11', executes: '4.1' },
  { control: '4.12', executes: '4.1' },
  { control: '4.13', executes: '4.1' },
  { control: '4.14', executes: '4.1' },
  { control: '5.3' },
];

const adminStack = new PlaybookPrimaryStack(app, 'CIS140Stack', {
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

const memberStack = new CIS140PlaybookMemberStack(app, 'CIS140MemberStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${SOLUTION_ID}C) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Member Account, ${DIST_VERSION}`,
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
