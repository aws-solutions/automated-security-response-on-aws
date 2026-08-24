#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { NIST80053PlaybookMemberStack } from '../lib/NIST80053_playbook-construct';
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';
import 'source-map-support/register';
import { PlaybookPrimaryStack } from '../../../lib/playbook-construct';
import { NIST80053_REMEDIATIONS } from '../lib/nist80053_remediations';
import { splitMemberStack } from '../../split_member_stacks';
import { getConfig, getMemberStackLimit } from '../../../lib/config/cdk-config';

const config = getConfig();
const MEMBER_STACK_LIMIT = getMemberStackLimit('NIST');

const standardShortName = 'NIST80053R5';
const standardLongName = 'nist-800-53';
const standardVersion = '5.0.0'; // DO NOT INCLUDE 'V'

const app = new App({
  context: {
    '@aws-cdk/core:suppressTemplateIndentation': true,
  },
});

const adminStack = new PlaybookPrimaryStack(app, 'NIST80053Stack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${config.solution.id}P) ${config.solution.name} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${config.build.distVersion}`,
  solutionId: config.solution.id,
  solutionVersion: config.build.distVersion,
  solutionDistBucket: config.build.distOutputBucket,
  solutionDistName: config.solution.trademarkedName,
  remediations: NIST80053_REMEDIATIONS,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});
adminStack.templateOptions.templateFormatVersion = '2010-09-09';

splitMemberStack({
  scope: app,
  stackClass: NIST80053PlaybookMemberStack,
  stackLimit: MEMBER_STACK_LIMIT,
  remediations: NIST80053_REMEDIATIONS,
  baseStackName: 'NIST80053MemberStack',
  standardShortName: standardShortName,
  standardVersion: standardVersion,
  standardLongName: standardLongName,
});
