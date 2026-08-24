#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import {
  SecurityControlsPlaybookMemberStack,
  SecurityControlsPlaybookPrimaryStack,
} from '../lib/security_controls_playbook-construct';
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';
import 'source-map-support/register';
import { SC_REMEDIATIONS } from '../lib/sc_remediations';
import { splitMemberStack } from '../../split_member_stacks';
import { getConfig, getMemberStackLimit } from '../../../lib/config/cdk-config';

const config = getConfig();
const MEMBER_STACK_LIMIT = getMemberStackLimit('SC');

const standardShortName = 'SC';
const standardLongName = 'security-control';
const standardVersion = '2.0.0'; // DO NOT INCLUDE 'V'

const app = new App();

const adminStack = new SecurityControlsPlaybookPrimaryStack(app, 'SCStack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${config.solution.id}P) ${config.solution.name} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${config.build.distVersion}`,
  solutionId: config.solution.id,
  solutionVersion: config.build.distVersion,
  solutionDistBucket: config.build.distOutputBucket,
  solutionDistName: config.solution.trademarkedName,
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
