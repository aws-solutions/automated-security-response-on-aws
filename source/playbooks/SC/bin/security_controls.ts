#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  SecurityControlsPlaybookMemberStack,
  SecurityControlsPlaybookPrimaryStack,
} from '../lib/security_controls_playbook-construct';
import { App, Aspects, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import 'source-map-support/register';
import { SC_REMEDIATIONS } from '../lib/sc_remediations';
import { splitMemberStack } from '../../split_member_stacks';

// set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
const MEMBER_STACK_LIMIT = process.env['SC_MEMBER_STACK_LIMIT']
  ? Number(process.env['SC_MEMBER_STACK_LIMIT'])
  : Infinity;
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'SC';
const standardLongName = 'security-control';
const standardVersion = '2.0.0'; // DO NOT INCLUDE 'V'

const app = new App();
Aspects.of(app).add(new AwsSolutionsChecks());

const adminStack = new SecurityControlsPlaybookPrimaryStack(app, 'SCStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${SOLUTION_ID}P) ${SOLUTION_NAME} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${DIST_VERSION}`,
  solutionId: SOLUTION_ID,
  solutionVersion: DIST_VERSION,
  solutionDistBucket: DIST_OUTPUT_BUCKET,
  solutionDistName: DIST_SOLUTION_NAME,
  remediations: SC_REMEDIATIONS,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});
adminStack.templateOptions.templateFormatVersion = '2010-09-09';

splitMemberStack({
  scope: app,
  stackClass: SecurityControlsPlaybookMemberStack,
  stackLimit: MEMBER_STACK_LIMIT,
  remediations: SC_REMEDIATIONS,
  baseStackName: 'SCMemberStack',
  standardShortName: standardShortName,
  standardVersion: standardVersion,
  standardLongName: standardLongName,
});
