/*****************************************************************************
 *  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.   *
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

import * as cdk from '@aws-cdk/core';
import * as logs from '@aws-cdk/aws-logs';
import * as sc from '@aws-cdk/aws-servicecatalog';
import * as iam from '@aws-cdk/aws-iam';
import * as s3 from '@aws-cdk/aws-s3';
import * as sns from '@aws-cdk/aws-sns';
import * as lambda from '@aws-cdk/aws-lambda';
import * as ssm from '@aws-cdk/aws-ssm';
import * as kms from '@aws-cdk/aws-kms';
import * as fs from 'fs';

export interface SHARRStackProps extends cdk.StackProps  {
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionTMN: string;
    solutionName: string;
}

export class SolutionDeployStack extends cdk.Stack {

  SEND_ANONYMOUS_DATA = 'Yes'

  constructor(scope: cdk.App, id: string, props: SHARRStackProps) {
    super(scope, id, props);
    
    const RESOURCE_PREFIX = props.solutionId; // prefix on every resource name

    //-------------------------------------------------------------------------
    // Solutions Bucket - Source Code
    //
    const SolutionsBucket = s3.Bucket.fromBucketAttributes(this, 'SolutionsBucket', {
        bucketName: props.solutionDistBucket + '-' + this.region
    });

    //=========================================================================
    // MAPPINGS
    //=========================================================================
    new cdk.CfnMapping(this, 'SourceCode', {
        mapping: { "General": { 
            "S3Bucket": props.solutionDistBucket,
            "KeyPrefix": props.solutionTMN + '/' + props.solutionVersion
        } }
    })

    //-------------------------------------------------------------------------
    // KMS Key for solution encryption
    //
    const kmsKey = new kms.Key(this, 'SHARR-key', {
        enableKeyRotation: true,
        alias: RESOURCE_PREFIX + '-SHARR-Key',
        trustAccountIdentities: true
    });

    new ssm.StringParameter(this, 'SHARR_Key', {
        description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
        parameterName: '/Solutions/' + RESOURCE_PREFIX + '/CMK_ARN',
        stringValue: kmsKey.keyArn
    });

    //-------------------------------------------------------------------------
    // SNS Topic for notification fanout on Playbook completion
    //
    const snsTopic = new sns.Topic(this, 'SHARR-Topic', {
        displayName: 'SHARR Playbook Topic (' + RESOURCE_PREFIX + ')',
        topicName: RESOURCE_PREFIX + '-SHARR_Topic',
        masterKey: kmsKey
    });

    new ssm.StringParameter(this, 'SHARR_SNS_Topic', {
        description: 'SNS Topic ARN where SHARR will send status messages. This\
        topic can be useful for driving additional actions, such as email notifications,\
        trouble ticket updates.',
        parameterName: '/Solutions/' + RESOURCE_PREFIX + '/SNS_Topic_ARN',
        stringValue: snsTopic.topicArn
    });

    const mapping = new cdk.CfnMapping(this, 'mappings');
    mapping.setValue("sendAnonymousMetrics", "data", this.SEND_ANONYMOUS_DATA)

	new ssm.StringParameter(this, 'SHARR_SendAnonymousMetrics', {
		description: 'Flag to enable or disable sending anonymous metrics.',
		parameterName: '/Solutions/' + RESOURCE_PREFIX + '/sendAnonymousMetrics',
		stringValue: mapping.findInMap("sendAnonymousMetrics", "data")
	});

	new ssm.StringParameter(this, 'SHARR_metricsId', {
		description: 'Stack Id for reference for metrics.',
		parameterName: '/Solutions/' + RESOURCE_PREFIX + '/metricsId',
		stringValue: this.stackId
	});

    //-------------------------------------------------------------------------
    // Custom Lambda Policy
    //
    const createCustomActionPolicy = new iam.Policy(this, 'createCustomActionPolicy', {
        policyName: RESOURCE_PREFIX + '-SHARR_Custom_Action',
        statements: [
            new iam.PolicyStatement({
                actions: [
                    'cloudwatch:PutMetricData'
                ],
                resources: ['*']
            }),
            new iam.PolicyStatement({
                actions: [
                    'logs:CreateLogGroup',
                    'logs:CreateLogStream',
                    'logs:PutLogEvents'
                ],
                resources: ['*']
            }),
            new iam.PolicyStatement({
                actions: [
                    'securityhub:CreateActionTarget',
                    'securityhub:DeleteActionTarget'
                ],
                resources: ['*']
            })
        ]
    })

    const createCAPolicyResource = createCustomActionPolicy.node.findChild('Resource') as iam.CfnPolicy;

    createCAPolicyResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W12',
                reason: 'Resource * is required for CloudWatch Logs policies used on Lambda functions.'
            }]
        }
    };

    //-------------------------------------------------------------------------
    // Custom Lambda Role
    //
    const createCustomActionRole = new iam.Role(this, 'createCustomActionRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        description: 'Lambda role to allow creation of Security Hub Custom Actions'
    });

    createCustomActionRole.attachInlinePolicy(createCustomActionPolicy);

    const createCARoleResource = createCustomActionRole.node.findChild('Resource') as iam.CfnRole;

    createCARoleResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W28',
                reason: 'Static names chosen intentionally to provide easy integration with playbook templates'
            }]
        }
    };

    //-------------------------------------------------------------------------
    // Custom Lambda - Create Custom Action
    //
    const createCustomAction = new lambda.Function(this, 'CreateCustomAction', {
        functionName: RESOURCE_PREFIX + '-SHARR-CustomAction',
        handler: 'createCustomAction.lambda_handler',
        runtime: lambda.Runtime.PYTHON_3_8,
        description: 'Custom resource to create an action target in Security Hub',
        code: lambda.Code.fromBucket(
            SolutionsBucket,
            props.solutionTMN + '/' + props.solutionVersion + '/lambda/createCustomAction.py.zip'
        ),
        environment: {
            log_level: 'info',
            sendAnonymousMetrics: mapping.findInMap("sendAnonymousMetrics", "data"),
            AWS_PARTITION: this.partition
        },
        memorySize: 256,
        timeout: cdk.Duration.seconds(60),
        role: createCustomActionRole
    });

    const createCAFuncResource = createCustomAction.node.findChild('Resource') as lambda.CfnFunction;

    createCAFuncResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W58',
                reason: 'False positive. See https://github.com/stelligent/cfn_nag/issues/422'
            }]
        }
    };

    //---------------------------------------------------------------------
    // Service Catalog Nested Stack
    //
    const serviceCatalog = new cdk.CfnStack(this, "PlaybookServiceCatalog", {
        parameters: {
            CreateCustomActionArn: createCustomAction.functionArn
        },
        templateUrl: "https://" + cdk.Fn.findInMap("SourceCode", "General", "S3Bucket") +
        "-reference.s3.amazonaws.com/" + cdk.Fn.findInMap("SourceCode", "General", "KeyPrefix") +
        "/aws-sharr-portolio-deploy.template"
    })
    serviceCatalog.cfnOptions.condition = new cdk.CfnCondition(this, "UseServiceCatalog", {
        expression: cdk.Fn.conditionNot(cdk.Fn.conditionEquals(this.partition, "aws-cn"))
    });
  }
}
