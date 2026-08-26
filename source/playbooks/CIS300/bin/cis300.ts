#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { PlaybookPrimaryStack } from '../../../lib/playbook-construct';
import * as cdk from 'aws-cdk-lib';
import 'source-map-support/register';
import { CIS300PlaybookMemberStack } from '../lib/cis300_playbook-construct';
import { CIS300_remediations } from '../lib/cis300_remediations';
import { splitMemberStack } from '../../split_member_stacks';
import { getConfig, getMemberStackLimit } from '../../../lib/config/cdk-config';

const config = getConfig();
const MEMBER_STACK_LIMIT = getMemberStackLimit('CIS300');

const standardShortName = 'CIS';
const standardLongName = 'cis-aws-foundations-benchmark';
const standardVersion = '3.0.0'; // DO NOT INCLUDE 'V'

const app = new cdk.App();

const adminStack = new PlaybookPrimaryStack(app, 'CIS300Stack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${config.solution.id}P) ${config.solution.name} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${config.build.distVersion}`,
  solutionId: config.solution.id,
  solutionVersion: config.build.distVersion,
  solutionDistBucket: config.build.distOutputBucket,
  solutionDistName: config.solution.trademarkedName,
  remediations: CIS300_remediations,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});
adminStack.templateOptions.templateFormatVersion = '2010-09-09';

splitMemberStack({
  scope: app,
  stackClass: CIS300PlaybookMemberStack,
  stackLimit: MEMBER_STACK_LIMIT,
  remediations: CIS300_remediations,
  baseStackName: 'CIS300MemberStack',
  standardShortName: standardShortName,
  standardVersion: standardVersion,
  standardLongName: standardLongName,
});
