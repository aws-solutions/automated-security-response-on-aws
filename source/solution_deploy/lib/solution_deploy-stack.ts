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
import { 
    PolicyStatement, 
    PolicyDocument, 
    ServicePrincipal,
    AccountRootPrincipal,
    Effect } from '@aws-cdk/aws-iam';

export interface SHARRStackProps extends cdk.StackProps  {
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionTMN: string;
    solutionName: string;
    runtimePython: lambda.Runtime;

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

    // Key Policy
    const kmsKeyPolicy:PolicyDocument = new PolicyDocument()
    
    const kmsServicePolicy = new PolicyStatement({
        principals: [
            new ServicePrincipal('sns.amazonaws.com'),
            new ServicePrincipal(`logs.${this.urlSuffix}`)
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
        ],
        conditions: {
            ArnEquals: {
                "kms:EncryptionContext:aws:logs:arn": this.formatArn({
                    service: 'logs',
                    resource: 'log-group:SO0111-SHARR-*' 
                })
            }
        }
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
    

    const kmsKey = new kms.Key(this, 'SHARR-key', {
        enableKeyRotation: true,
        alias: RESOURCE_PREFIX + '-SHARR-Key',
        trustAccountIdentities: true,
        policy: kmsKeyPolicy
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

    new ssm.StringParameter(this, 'SHARR_version', {
        description: 'Solution version for metrics.',
        parameterName: '/Solutions/' + RESOURCE_PREFIX + '/version',
        stringValue: props.solutionVersion
    });

    /**
     * @description Lambda Layer for common solution functions
     * @type {lambda.LayerVersion}
     */
    const sharrLambdaLayer = new lambda.LayerVersion(this, 'SharrLambdaLayer', {
        compatibleRuntimes: [
            lambda.Runtime.PYTHON_3_6,
            lambda.Runtime.PYTHON_3_7,
            lambda.Runtime.PYTHON_3_8
        ],
        description: 'SO0111 SHARR Common functions used by the solution',
        license: "https://www.apache.org/licenses/LICENSE-2.0",
        code: lambda.Code.fromBucket(
            SolutionsBucket,
            props.solutionTMN + '/' + props.solutionVersion + '/lambda/layer.zip'
        ), 
    });

    /**
     * @description Policy for role used by common Orchestrator Lambdas
     * @type {iam.Policy}
     */
    const orchestratorPolicy = new iam.Policy(this, 'orchestratorPolicy', {
        policyName: RESOURCE_PREFIX + '-SHARR_Orchestrator',
        statements: [
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
                    'ssm:GetParameter',
                    'ssm:GetParameters',
                    'ssm:PutParameter'
                ],
                resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`]
            }),
            new iam.PolicyStatement({
                 actions: [
                    'sts:AssumeRole'
                ],
                resources: [
                    'arn:' + this.partition + ':iam::*:role/' + RESOURCE_PREFIX +
                        '-SHARR-Orchestrator-Member-*_' + this.region,
                    'arn:' + this.partition + ':iam::*:role/' + RESOURCE_PREFIX +
                        '-SHARR-Remediation-*', 
                ]
            })
        ]
    })

    {
        let childToMod = orchestratorPolicy.node.findChild('Resource') as iam.CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for read-only policies used by orchestrator Lambda functions.'
                }]
            }
        }
    }

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {iam.Role}
     */

    const orchestratorRole = new iam.Role(this, 'orchestratorRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        description: 'Lambda role to allow cross account read-only SHARR orchestrator functions',
        roleName: props.solutionId + '-SHARR-Orchestrator-Admin_' + this.region
    });

    orchestratorRole.attachInlinePolicy(orchestratorPolicy);

    {
        let childToMod = orchestratorRole.node.findChild('Resource') as iam.CfnRole;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide easy integration with playbook orchestrator step functions.'
                }]
            }
        }
    }

    /**
     * @description checkSSMDocState - get the status of an ssm document
     * @type {lambda.Function}
     */
    const checkSSMDocState = new lambda.Function(this, 'checkSSMDocState', {
        functionName: RESOURCE_PREFIX + '-SHARR-checkSSMDocState',
        handler: 'check_ssm_doc_state.lambda_handler',
        runtime: props.runtimePython,
        description: 'Checks the status of an SSM Automation Document in the target account',
        code: lambda.Code.fromBucket(
            SolutionsBucket,
            props.solutionTMN + '/' + props.solutionVersion + '/lambda/check_ssm_doc_state.py.zip'
        ),
        environment: {
            log_level: 'info',
            sendAnonymousMetrics: mapping.findInMap("sendAnonymousMetrics", "data"),
            AWS_PARTITION: this.partition
        },
        memorySize: 256,
        timeout: cdk.Duration.seconds(60),
        role: orchestratorRole,
        layers: [sharrLambdaLayer]
    });

    {
        const childToMod = checkSSMDocState.node.findChild('Resource') as lambda.CfnFunction;

        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [
                {
                    id: 'W58',
                    reason: 'False positive. Access is provided via a policy'
                },
                {
                    id: 'W89',
                    reason: 'There is no need to run this lambda in a VPC'
                },
                {
                    id: 'W92',
                    reason: 'There is no need for Reserved Concurrency'
                }
                ]
            }
        };
    }

    /**
     * @description execAutomation - initiate an SSM automation document in a target account
     * @type {lambda.Function}
     */
    const execAutomation = new lambda.Function(this, 'execAutomation', {
        functionName: RESOURCE_PREFIX + '-SHARR-execAutomation',
        handler: 'exec_ssm_doc.lambda_handler',
        runtime: props.runtimePython,
        description: 'Executes an SSM Automation Document in a target account',
        code: lambda.Code.fromBucket(
            SolutionsBucket,
            props.solutionTMN + '/' + props.solutionVersion + '/lambda/exec_ssm_doc.py.zip'
        ),
        environment: {
            log_level: 'info',
            sendAnonymousMetrics: mapping.findInMap("sendAnonymousMetrics", "data"),
            AWS_PARTITION: this.partition
        },
        memorySize: 256,
        timeout: cdk.Duration.seconds(60),
        role: orchestratorRole,
        layers: [sharrLambdaLayer]
    });

    {
        const childToMod = execAutomation.node.findChild('Resource') as lambda.CfnFunction;

        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W58',
                    reason: 'False positive. Access is provided via a policy'
                },{
                    id: 'W89',
                    reason: 'There is no need to run this lambda in a VPC'
                },
                {
                    id: 'W92',
                    reason: 'There is no need for Reserved Concurrency'
                }]
            }
        };
    }

    /**
     * @description monitorSSMExecState - get the status of an ssm execution
     * @type {lambda.Function}
     */
    const monitorSSMExecState = new lambda.Function(this, 'monitorSSMExecState', {
        functionName: RESOURCE_PREFIX + '-SHARR-monitorSSMExecState',
        handler: 'check_ssm_execution.lambda_handler',
        runtime: props.runtimePython,
        description: 'Checks the status of an SSM automation document execution',
        code: lambda.Code.fromBucket(
            SolutionsBucket,
            props.solutionTMN + '/' + props.solutionVersion + '/lambda/check_ssm_execution.py.zip'
        ),
        environment: {
            log_level: 'info',
            sendAnonymousMetrics: mapping.findInMap("sendAnonymousMetrics", "data"),
            AWS_PARTITION: this.partition
        },
        memorySize: 256,
        timeout: cdk.Duration.seconds(60),
        role: orchestratorRole,
        layers: [sharrLambdaLayer]
    });

    {
        const childToMod = monitorSSMExecState.node.findChild('Resource') as lambda.CfnFunction;

        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W58',
                    reason: 'False positive. Access is provided via a policy'
                },{
                    id: 'W89',
                    reason: 'There is no need to run this lambda in a VPC'
                },
                {
                    id: 'W92',
                    reason: 'There is no need for Reserved Concurrency'
                }]
            }
        };
    }

    /**
     * @description Policy for role used by common Orchestrator notification lambda
     * @type {iam.Policy}
     */
    const notifyPolicy = new iam.Policy(this, 'notifyPolicy', {
        policyName: RESOURCE_PREFIX + '-SHARR_Orchestrator_Notifier',
        statements: [
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
                    'securityhub:BatchUpdateFindings'
                ],
                resources: ['*']
            }),
            new iam.PolicyStatement({
                actions: [
                    'ssm:GetParameter'
                ],
                resources: [`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`]
            }),
            new iam.PolicyStatement({
                actions: [
                    'kms:Encrypt',
                    'kms:Decrypt',
                    'kms:GenerateDataKey',
                ],
                resources: [kmsKey.keyArn]
            }),
            new iam.PolicyStatement({
                actions: [
                    'sns:Publish'
                ],
                resources: ['arn:' + this.partition + ':sns:' + this.region + ':' +
                    this.account + ':' + props.solutionId + '-SHARR_Topic']
            })
        ]
    })

    {
        let childToMod = notifyPolicy.node.findChild('Resource') as iam.CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for CloudWatch Logs and Security Hub policies used by core solution Lambda function for notifications.'
                },{
                    id: 'W58',
                    reason: 'False positive. Access is provided via a policy'
                }]
            }
        }
    }

    /**
     * @description Role used by common Orchestrator Lambdas
     * @type {iam.Role}
     */

    const notifyRole = new iam.Role(this, 'notifyRole', {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        description: 'Lambda role to perform notification and logging from orchestrator step function'
    });

    notifyRole.attachInlinePolicy(notifyPolicy);

    {
        let childToMod = notifyRole.node.findChild('Resource') as iam.CfnRole;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide easy integration with playbook orchestrator step functions.'
                }]
            }
        }
    }

    /**
     * @description sendNotifications - send notifications and log messages from Orchestrator step function
     * @type {lambda.Function}
     */
    const sendNotifications = new lambda.Function(this, 'sendNotifications', {
        functionName: RESOURCE_PREFIX + '-SHARR-sendNotifications',
        handler: 'send_notifications.lambda_handler',
        runtime: props.runtimePython,
        description: 'Sends notifications and log messages',
        code: lambda.Code.fromBucket(
            SolutionsBucket,
            props.solutionTMN + '/' + props.solutionVersion + '/lambda/send_notifications.py.zip'
        ),
        environment: {
            log_level: 'info',
            sendAnonymousMetrics: mapping.findInMap("sendAnonymousMetrics", "data"),
            AWS_PARTITION: this.partition
        },
        memorySize: 256,
        timeout: cdk.Duration.seconds(60),
        role: notifyRole,
        layers: [sharrLambdaLayer]
    });

    {
        const childToMod = sendNotifications.node.findChild('Resource') as lambda.CfnFunction;

        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W58',
                    reason: 'False positive. Access is provided via a policy'
                },{
                    id: 'W89',
                    reason: 'There is no need to run this lambda in a VPC'
                },
                {
                    id: 'W92',
                    reason: 'There is no need for Reserved Concurrency due to low request rate'
                }]
            }
        };
    }

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
        runtime: props.runtimePython,
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
        role: createCustomActionRole,
        layers: [sharrLambdaLayer]
    });

    const createCAFuncResource = createCustomAction.node.findChild('Resource') as lambda.CfnFunction;

    createCAFuncResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W58',
                reason: 'False positive. See https://github.com/stelligent/cfn_nag/issues/422'
            },{
                id: 'W89',
                reason: 'There is no need to run this lambda in a VPC'
            },
            {
                id: 'W92',
                reason: 'There is no need for Reserved Concurrency due to low request rate'
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
