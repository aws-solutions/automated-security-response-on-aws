#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { PlaybookMemberStack, PlaybookPrimaryStack } from '../../../lib/playbook-construct';
import * as cdk from 'aws-cdk-lib';
import 'source-map-support/register';
import { AFSBP_REMEDIATIONS } from '../lib/afsbp_remediations';
import { splitMemberStack } from '../../split_member_stacks';
import { getConfig, getMemberStackLimit } from '../../../lib/config/cdk-config';

const config = getConfig();
const standardShortName = 'AFSBP';
const MEMBER_STACK_LIMIT = getMemberStackLimit(standardShortName);
const standardLongName = 'aws-foundational-security-best-practices';
const standardVersion = '1.0.0'; // DO NOT INCLUDE 'V'

const app = new cdk.App();

const adminStack = new PlaybookPrimaryStack(app, 'AFSBPStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${config.solution.id}P) ${config.solution.name} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${config.build.distVersion}`,
  solutionId: config.solution.id,
  solutionVersion: config.build.distVersion,
  solutionDistBucket: config.build.distOutputBucket,
  solutionDistName: config.solution.trademarkedName,
  remediations: AFSBP_REMEDIATIONS,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});
adminStack.templateOptions.templateFormatVersion = '2010-09-09';

splitMemberStack({
  scope: app,
  stackClass: PlaybookMemberStack,
  stackLimit: MEMBER_STACK_LIMIT,
  remediations: AFSBP_REMEDIATIONS,
  baseStackName: 'AFSBPMemberStack',
  standardShortName: standardShortName,
  standardVersion: standardVersion,
  standardLongName: standardLongName,
});
