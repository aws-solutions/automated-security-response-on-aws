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

import { SynthUtils } from '@aws-cdk/assert';
import '@aws-cdk/assert/jest';
import { App, Stack } from '@aws-cdk/core';
import { OrchestratorConstruct } from '../Orchestrator/lib/common-orchestrator-construct';
import * as kms from '@aws-cdk/aws-kms';
import { StringParameter } from '@aws-cdk/aws-ssm';
import { 
    PolicyStatement, 
    PolicyDocument, 
    ServicePrincipal,
    AccountRootPrincipal,
} from '@aws-cdk/aws-iam';
import { AwsSolutionsChecks } from 'cdk-nag'
import { Aspects } from '@aws-cdk/core'

test('test App Orchestrator Construct', () => {

    const app = new App();
    const stack = new Stack(app, 'testStack', {
        stackName: 'testStack'
    });

    const kmsKeyPolicy:PolicyDocument = new PolicyDocument()
    
    const kmsServicePolicy = new PolicyStatement({
        principals: [
            new ServicePrincipal('sns.amazonaws.com'),
            new ServicePrincipal(`logs.${stack.urlSuffix}`)
        ],
        actions: [
            "kms:Encrypt*",
            "kms:Decrypt*",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:Describe*"
        ],
        resources: [
            '*'
        ]
    })
    kmsKeyPolicy.addStatements(kmsServicePolicy)

    const kmsRootPolicy = new PolicyStatement({
        principals: [
            new AccountRootPrincipal()
        ],
        actions: [
            'kms:*'
        ],
        resources: [
            '*'
        ]
    })
    kmsKeyPolicy.addStatements(kmsRootPolicy)

    const kmsKey = new kms.Key(stack, 'SHARR-key', {
        enableKeyRotation: true,
        alias: 'TO0111-SHARR-Key',
        policy: kmsKeyPolicy
    });

    const kmsKeyParm = new StringParameter(stack, 'SHARR_Key', {
        description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
        parameterName: `/Solutions/SO0111/CMK_ARN`,
        stringValue: kmsKey.keyArn
    });

    new OrchestratorConstruct(stack, 'Orchestrator', {
	    roleArn: 'arn:aws-test:iam::111122223333:role/TestRole',
	    ssmDocStateLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
	    ssmExecDocLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
	    ssmExecMonitorLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
	    notifyLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
        getApprovalRequirementLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
        solutionId: 'bbb',
        solutionName: 'This is a test',
        solutionVersion: '1.1.1',
        orchLogGroup: 'ORCH_LOG_GROUP',
        kmsKeyParm: kmsKeyParm
    });
    Aspects.of(app).add(new AwsSolutionsChecks({verbose: true}))
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});