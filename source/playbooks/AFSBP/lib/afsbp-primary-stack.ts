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

//
// Primary Stack - launched by Service Catalog in the Security Hub Admin account
// Creates CWE rules and custom actions, orchestrator step function
// Orchestrator lambdas are common to all Playbooks and deployed in the main stack
//
import * as cdk from '@aws-cdk/core';
import { Trigger } from '../../../lib/playbook-construct';
import { OrchestratorConstruct } from '../lib/afsbp-orchestrator-construct';

export interface MyStackProps {
    description: string;
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionDistName: string;
    solutionName: string;
}

export class AfsbpPrimaryStack extends cdk.Stack {

  constructor(scope: cdk.Construct, id: string, props: MyStackProps) {
    super(scope, id, props);

    new cdk.CfnMapping(this, 'SourceCode', {
        mapping: { "General": { 
            "S3Bucket": props.solutionDistBucket,
            "KeyPrefix": props.solutionDistName + '/' + props.solutionVersion
        } }
    })

    const orchestrator:OrchestratorConstruct = new OrchestratorConstruct(this, "orchestrator", {
        roleArn: 'arn:' + this.partition + ':iam:' + this.region + ':' +
            this.account + ':role/' + props.solutionId + '-SHARR-Orchestrator-Admin_' +
            this.region,
        ssmDocStateLambda: 'arn:' + this.partition + ':lambda:' + this.region + ':' +
            this.account + ':function:' + props.solutionId + '-SHARR-checkSSMDocState',
        ssmExecDocLambda: 'arn:' + this.partition + ':lambda:' + this.region + ':' +
            this.account + ':function:' + props.solutionId + '-SHARR-execAutomation',
        ssmExecMonitorLambda: 'arn:' + this.partition + ':lambda:' + this.region + ':' +
            this.account + ':function:' + props.solutionId + '-SHARR-monitorSSMExecState',
        notifyLambda: 'arn:' + this.partition + ':lambda:' + this.region + ':' +
            this.account + ':function:' + props.solutionId + '-SHARR-sendNotifications',
        solutionId: props.solutionId
    })

    const remediations = [
        'AutoScaling.1',
        'CloudTrail.1',
        'CloudTrail.2',
        'Config.1',
        'EC2.1',
        'EC2.2',
        'EC2.7',
        'Lambda.1',
        'RDS.1',
        'RDS.6',
        'RDS.7',
        'S3.8'
    ]

    for (let controlId of remediations) {
        new Trigger(this, 'AFSBP ' + controlId, {
            securityStandard: 'AFSBP',
            securityStandardArn: 'arn:' + this.partition +
                ':securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0',
            controlId: controlId,
            targetArn: orchestrator.orchestratorArn
        })
    }

  }
}
