// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../lib/sharrplaybook-construct';
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';

// SOLUTION_* - set by solution_env.sh
const SOLUTION_ID = process.env['SOLUTION_ID'] || 'SO0111';
const SOLUTION_NAME = process.env['SOLUTION_NAME'] || 'Automated Security Response on AWS';
// DIST_* - set by build-s3-dist.sh
const DIST_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
const DIST_OUTPUT_BUCKET = process.env['DIST_OUTPUT_BUCKET'] || '%%BUCKET%%';

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
  const numDivisions = isFinite(props.stackLimit) ? Math.ceil(props.remediations.length / props.stackLimit) : 1;

  for (let stackIndex = 0; stackIndex < numDivisions; stackIndex++) {
    const stackName = stackIndex === 0 ? props.baseStackName : `${props.baseStackName}${stackIndex}`;
    const start = stackIndex * (isFinite(props.stackLimit) ? props.stackLimit : props.remediations.length);
    const end = start + (isFinite(props.stackLimit) ? props.stackLimit : props.remediations.length);
    const remediationsSubset: IControl[] = props.remediations.slice(start, end);

    const memberStack = new props.stackClass(props.scope, stackName, {
      analyticsReporting: false, // CDK::Metadata breaks StackSets in some regions
      synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      description: `(${SOLUTION_ID}) ${SOLUTION_NAME} ${props.standardShortName} ${props.standardVersion} Compliance Pack ${stackIndex} - Member Account, ${DIST_VERSION}`,
      solutionId: SOLUTION_ID,
      solutionVersion: DIST_VERSION,
      solutionDistBucket: DIST_OUTPUT_BUCKET,
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
