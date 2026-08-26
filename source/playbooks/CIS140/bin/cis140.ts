#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { PlaybookPrimaryStack } from '../../../lib/playbook-construct';
import * as cdk from 'aws-cdk-lib';
import 'source-map-support/register';
import { CIS140PlaybookMemberStack } from '../lib/cis140_playbook-construct';
import { CIS140_REMEDIATIONS } from '../lib/cis140_remediations';
import { splitMemberStack } from '../../split_member_stacks';
import { getConfig, getMemberStackLimit } from '../../../lib/config/cdk-config';

const config = getConfig();
const MEMBER_STACK_LIMIT = getMemberStackLimit('CIS140');

const standardShortName = 'CIS';
const standardLongName = 'cis-aws-foundations-benchmark';
const standardVersion = '1.4.0'; // DO NOT INCLUDE 'V'

const app = new cdk.App();

const adminStack = new PlaybookPrimaryStack(app, 'CIS140Stack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${config.solution.id}P) ${config.solution.name} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${config.build.distVersion}`,
  solutionId: config.solution.id,
  solutionVersion: config.build.distVersion,
  solutionDistBucket: config.build.distOutputBucket,
  solutionDistName: config.solution.trademarkedName,
  remediations: CIS140_REMEDIATIONS,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});
adminStack.templateOptions.templateFormatVersion = '2010-09-09';

splitMemberStack({
  scope: app,
  stackClass: CIS140PlaybookMemberStack,
  stackLimit: MEMBER_STACK_LIMIT,
  remediations: CIS140_REMEDIATIONS,
  baseStackName: 'CIS140MemberStack',
  standardShortName: standardShortName,
  standardVersion: standardVersion,
  standardLongName: standardLongName,
});
