/*****************************************************************************
 *  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License"). You may   *
 *  not use this file except in compliance with the License. A copy of the    *
 *  License is located at                                                     *
 *                                                                            *
 *      http://www.apache.org/licenses/LICENSE-2.0                            *
 *                                                                            *
 *  or in the 'license' file accompanying this file. This file is distributed *
 *  on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,        *
 *  express or implied. See the License for the specific language governing   *
 *  permissions and limitations under the License.                            *
 *****************************************************************************/

import { expect as expectCDK, matchTemplate, SynthUtils } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import {  PlaybookPrimaryStack, PlaybookMemberStack  } from '../../../lib/sharrplaybook-construct';

function getTestStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookPrimaryStack(app, 'stack', {
  	description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'aws-security-hub-automated-response-and-remediation',
    remediations: [ {"control":'Example.3'}, {"control":'Example.5'}, {"control":'Example.1'} ],
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
    securityStandardVersion: '3.2.1'
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getTestStack())).toMatchSnapshot();
});

function getMemberStack(): cdk.Stack {
  const app = new cdk.App();
  const stack = new PlaybookMemberStack(app, 'memberStack', {
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'playbooks/NEWPLAYBOOK/ssmdocs',
    remediations: [ {"control":'Example.3'}, {"control":'Example.5'}, {"control":'Example.1'} ],
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
    securityStandardVersion: '3.2.1'
  })
  return stack;
}

test('default stack', () => {
  expect(SynthUtils.toCloudFormation(getMemberStack())).toMatchSnapshot();
});