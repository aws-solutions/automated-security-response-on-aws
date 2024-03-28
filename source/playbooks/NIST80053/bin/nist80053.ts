#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { NIST80053PlaybookMemberStack } from '../lib/NIST80053_playbook-construct';
import { App, Aspects, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import 'source-map-support/register';
import { PlaybookPrimaryStack, IControl } from '../../../lib/sharrplaybook-construct';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'undefined';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'undefined';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';
const DIST_SOLUTION_NAME = process.env['DIST_SOLUTION_NAME'] || '%%SOLUTION%%';

const standardShortName = 'NIST80053R5';
const standardLongName = 'nist-800-53';
const standardVersion = '5.0.0'; // DO NOT INCLUDE 'V'

const app = new App();
Aspects.of(app).add(new AwsSolutionsChecks());

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
const remediations: IControl[] = [
  { control: 'AutoScaling.1' },
  { control: 'CloudFormation.1' },
  { control: 'CloudFront.1' },
  { control: 'CloudFront.12' },
  { control: 'CloudTrail.1' },
  { control: 'CloudTrail.2' },
  { control: 'CloudTrail.4' },
  { control: 'CloudTrail.5' },
  { control: 'CodeBuild.2' },
  { control: 'CodeBuild.5' },
  { control: 'Config.1' },
  { control: 'EC2.1' },
  { control: 'EC2.2' },
  { control: 'EC2.4' },
  { control: 'EC2.6' },
  { control: 'EC2.7' },
  { control: 'EC2.8' },
  { control: 'EC2.13' },
  { control: 'EC2.15' },
  { control: 'EC2.18' },
  { control: 'EC2.19' },
  { control: 'EC2.23' },
  { control: 'IAM.3' },
  { control: 'IAM.7' },
  { control: 'IAM.8' },
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
  { control: 'S3.9' },
  { control: 'S3.11' },
  { control: 'S3.13' },
  { control: 'SecretsManager.1' },
  { control: 'SecretsManager.3' },
  { control: 'SecretsManager.4' },
  { control: 'SNS.1' },
  { control: 'SNS.2' },
  { control: 'SQS.1' },
  { control: 'SSM.4' },
];

const adminStack = new PlaybookPrimaryStack(app, 'NIST80053Stack', {
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

const memberStack = new NIST80053PlaybookMemberStack(app, 'NIST80053MemberStack', {
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
