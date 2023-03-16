#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  SecurityControlsPlaybookPrimaryStack,
  SecurityControlsPlaybookMemberStack,
} from '../lib/security_controls_playbook-construct';
import { App, Aspects, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import 'source-map-support/register';
import { IControl } from '../../../lib/sharrplaybook-construct';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'SC';
const standardLongName = 'security-control';
const standardVersion = '2.0.0'; // DO NOT INCLUDE 'V'

const app = new App();
Aspects.of(app).add(new AwsSolutionsChecks());

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
const remediations: IControl[] = [
  { control: 'AutoScaling.1' },
  { control: 'CloudTrail.1' },
  { control: 'CloudTrail.2' },
  { control: 'CloudTrail.3', executes: 'CloudTrail.1' },
  { control: 'CloudTrail.4' },
  { control: 'CloudTrail.5' },
  { control: 'CloudTrail.6' },
  { control: 'CloudTrail.7' },
  { control: 'CloudWatch.1' },
  { control: 'CloudWatch.2', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.3', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.4', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.5', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.6', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.7', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.8', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.9', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.10', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.11', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.12', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.13', executes: 'CloudWatch.1' },
  { control: 'CloudWatch.14', executes: 'CloudWatch.1' },
  { control: 'CodeBuild.2' },
  { control: 'Config.1' },
  { control: 'EC2.1' },
  { control: 'EC2.2' },
  { control: 'EC2.6' },
  { control: 'EC2.7' },
  { control: 'EC2.13' },
  { control: 'EC2.14', executes: 'EC2.13' },
  { control: 'IAM.3' },
  { control: 'IAM.7' },
  { control: 'IAM.8' },
  { control: 'IAM.11', executes: 'IAM.7' },
  { control: 'IAM.12', executes: 'IAM.7' },
  { control: 'IAM.13', executes: 'IAM.7' },
  { control: 'IAM.14', executes: 'IAM.7' },
  { control: 'IAM.15', executes: 'IAM.7' },
  { control: 'IAM.16', executes: 'IAM.7' },
  { control: 'IAM.17', executes: 'IAM.7' },
  { control: 'IAM.18' },
  { control: 'IAM.22' },
  { control: 'KMS.4' },
  { control: 'Lambda.1' },
  { control: 'RDS.1' },
  { control: 'RDS.2' },
  { control: 'RDS.4' },
  { control: 'RDS.5' },
  { control: 'RDS.6' },
  { control: 'RDS.7' },
  { control: 'RDS.8' },
  { control: 'RDS.13' },
  { control: 'RDS.16' },
  { control: 'Redshift.1' },
  { control: 'Redshift.3' },
  { control: 'Redshift.4' },
  { control: 'Redshift.6' },
  { control: 'S3.1' },
  { control: 'S3.2' },
  { control: 'S3.3', executes: 'S3.2' },
  { control: 'S3.4' },
  { control: 'S3.5' },
  { control: 'S3.6' },
  { control: 'S3.8', executes: 'S3.2' },
];

const adminStack = new SecurityControlsPlaybookPrimaryStack(app, 'SCStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
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

const memberStack = new SecurityControlsPlaybookMemberStack(app, 'SCMemberStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
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
