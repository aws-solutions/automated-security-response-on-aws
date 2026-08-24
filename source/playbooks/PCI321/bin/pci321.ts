#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { PlaybookPrimaryStack, PlaybookMemberStack } from '../../../lib/playbook-construct';
import * as cdk from 'aws-cdk-lib';
import 'source-map-support/register';
import { PCI321_REMEDIATIONS } from '../lib/pci321_remediations';
import { splitMemberStack } from '../../split_member_stacks';
import { getConfig, getMemberStackLimit } from '../../../lib/config/cdk-config';

const config = getConfig();
const MEMBER_STACK_LIMIT = getMemberStackLimit('PCI321');

const standardShortName = 'PCI';
const standardLongName = 'pci-dss';
const standardVersion = '3.2.1'; // DO NOT INCLUDE 'V'

const app = new cdk.App();

const adminStack = new PlaybookPrimaryStack(app, 'PCI321Stack', {
  analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
  synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
  description: `(${config.solution.id}P) ${config.solution.name} ${standardShortName} ${standardVersion} Compliance Pack - Admin Account, ${config.build.distVersion}`,
  solutionId: config.solution.id,
  solutionVersion: config.build.distVersion,
  solutionDistBucket: config.build.distOutputBucket,
  solutionDistName: config.solution.trademarkedName,
  remediations: PCI321_REMEDIATIONS,
  securityStandardLongName: standardLongName,
  securityStandard: standardShortName,
  securityStandardVersion: standardVersion,
});
adminStack.templateOptions.templateFormatVersion = '2010-09-09';

splitMemberStack({
  scope: app,
  stackClass: PlaybookMemberStack,
  stackLimit: MEMBER_STACK_LIMIT,
  remediations: PCI321_REMEDIATIONS,
  baseStackName: 'PCI321MemberStack',
  standardShortName: standardShortName,
  standardVersion: standardVersion,
  standardLongName: standardLongName,
});
