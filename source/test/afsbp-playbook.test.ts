#!/usr/bin/env node
/*****************************************************************************
 *  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
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

import { SynthUtils } from '@aws-cdk/assert';
import '@aws-cdk/assert/jest';
import { BlockPublicAccess, Bucket, BucketAccessControl, BucketEncryption } from '@aws-cdk/aws-s3';
import { App, Stack } from '@aws-cdk/core';
import { OrchestratorConstruct } from '../playbooks/AFSBP/lib/afsbp-orchestrator-construct';

test('test App AFSBP Orchestrator Construct', () => {

    const app = new App();
    const stack = new Stack(app, 'testStack', {
        stackName: 'testStack'
    });

    new OrchestratorConstruct(stack, 'Orchestrator', {
	    roleArn: 'arn:aws-test:iam::111111111111:role/TestRole',
	    ssmDocStateLambda: 'xxx',
	    ssmExecDocLambda: 'yyy',
	    ssmExecMonitorLambda: 'zzz',
	    notifyLambda: 'aaa',
        solutionId: 'bbb'
    });

    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});