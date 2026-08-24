// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../lib/playbook-construct';
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { getConfig } from '../lib/config/cdk-config';

const config = getConfig();

export interface SplitStackProps {
  scope: App;
  stackClass: new (...args: any[]) => any;
  stackLimit: number;
  remediations: IControl[];
  baseStackName: string;
  standardShortName: string;
  standardVersion: string;
  standardLongName: string;
}

/**
 * Split stacks into multiple stacks to avoid reaching template size limit
 */
export function splitMemberStack(props: SplitStackProps): any[] {
  const memberStacks = [];
  const numDivisions = Number.isFinite(props.stackLimit) ? Math.ceil(props.remediations.length / props.stackLimit) : 1;

  for (let stackIndex = 0; stackIndex < numDivisions; stackIndex++) {
    const stackName = stackIndex === 0 ? props.baseStackName : `${props.baseStackName}${stackIndex}`;
    const start = stackIndex * (Number.isFinite(props.stackLimit) ? props.stackLimit : props.remediations.length);
    const end = start + (Number.isFinite(props.stackLimit) ? props.stackLimit : props.remediations.length);
    const remediationsSubset: IControl[] = props.remediations.slice(start, end);

    const memberStack = new props.stackClass(props.scope, stackName, {
      analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: `(${config.solution.id}PM) ${config.solution.name} ${props.standardShortName} ${props.standardVersion} Compliance Pack ${stackIndex} - Member Account, ${config.build.distVersion}`,
      solutionId: config.solution.id,
      solutionVersion: config.build.distVersion,
      solutionDistBucket: config.build.distOutputBucket,
      securityStandard: props.standardShortName,
      securityStandardVersion: props.standardVersion,
      securityStandardLongName: props.standardLongName,
      remediations: remediationsSubset,
    });

    memberStack.templateOptions.templateFormatVersion = '2010-09-09';
    memberStacks.push(memberStack);
  }

  return memberStacks;
}
