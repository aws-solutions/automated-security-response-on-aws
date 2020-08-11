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


export class SolutionDeployStack extends cdk.Stack {

    SOLUTION_NAME = process.env['SOLUTION_NAME'];
    SOLUTION_TMN = process.env['SOLUTION_TRADEMARKEDNAME'];
    SOLUTION_VERSION = process.env['DIST_VERSION'] || '%%VERSION%%';
    SOLUTION_PROVIDER = 'AWS Solution Development';
    SOLUTION_BUCKET = process.env['DIST_OUTPUT_BUCKET'];
    SC_DESCRIPTION = 'Portfolio of available ' + this.SOLUTION_NAME + ' Playbooks. See https://aws.amazon.com/solutions/implementations/aws-security-hub-automated-response-and-remediation/';
    RESOURCE_PREFIX = process.env['SOLUTION_ID']; // prefix on every resource name
    SEND_ANONYMOUS_DATA = 'Yes'

    constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const solutionId = this.node.tryGetContext('solutionId')

        //-------------------------------------------------------------------------
        // Solutions Bucket - Source Code
        //
        const SolutionsBucket = s3.Bucket.fromBucketAttributes(this, 'SolutionsBucket', {
            bucketName: this.SOLUTION_BUCKET + '-' + this.region
        });

        //-------------------------------------------------------------------------
        // Configure log group for short retention
        //
        const logGroup = new logs.LogGroup(this, 'SHARR-Logs', {
            logGroupName: this.RESOURCE_PREFIX + '-SHARR',
            removalPolicy: cdk.RemovalPolicy.RETAIN,
            retention: logs.RetentionDays.ONE_YEAR
        });

        //-------------------------------------------------------------------------
        // Configure ServiceCatalog Portfolio
        //
        const solPortfolio = new sc.CfnPortfolio(this, 'SC-Playbooks', {
            displayName: 'Security Hub Playbooks (' + this.RESOURCE_PREFIX + ')',
            providerName: this.SOLUTION_PROVIDER,
            description: this.SC_DESCRIPTION
        });

        //-------------------------------------------------------------------------
        // KMS Key for solution encryption
        //
        const kmsKey = new kms.Key(this, 'SHARR-key', {
            enableKeyRotation: true,
            alias: this.RESOURCE_PREFIX + '-SHARR-Key',
            trustAccountIdentities: true
        });

        new ssm.StringParameter(this, 'SHARR_Key', {
            description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
            parameterName: '/Solutions/' + this.RESOURCE_PREFIX + '/CMK_ARN',
            stringValue: kmsKey.keyArn
        });

        //-------------------------------------------------------------------------
        // SNS Topic for notification fanout on Playbook completion
        //
        const snsTopic = new sns.Topic(this, 'SHARR-Topic', {
            displayName: 'SHARR Playbook Topic (' + this.RESOURCE_PREFIX + ')',
            topicName: this.RESOURCE_PREFIX + '-SHARR_Topic',
            masterKey: kmsKey
        });

        new ssm.StringParameter(this, 'SHARR_SNS_Topic', {
            description: 'SNS Topic ARN where SHARR will send status messages. This\
            topic can be useful for driving additional actions, such as email notifications,\
            trouble ticket updates.',
            parameterName: '/Solutions/' + this.RESOURCE_PREFIX + '/SNS_Topic_ARN',
            stringValue: snsTopic.topicArn
        });

        const mapping = new cdk.CfnMapping(this, 'mappings');
        mapping.setValue("sendAnonymousMetrics", "data", this.SEND_ANONYMOUS_DATA)

		new ssm.StringParameter(this, 'SHARR_SendAnonymousMetrics', {
			description: 'Flag to enable or disable sending anonymous metrics.',
			parameterName: '/Solutions/' + this.RESOURCE_PREFIX + '/sendAnonymousMetrics',
			stringValue: mapping.findInMap("sendAnonymousMetrics", "data")
		});

		new ssm.StringParameter(this, 'SHARR_metricsId', {
			description: 'Stack Id for reference for metrics.',
			parameterName: '/Solutions/' + this.RESOURCE_PREFIX + '/metricsId',
			stringValue: this.stackId
		});

        //-------------------------------------------------------------------------
        // Custom Lambda Policy
        //
        const createCustomActionPolicy = new iam.Policy(this, 'createCustomActionPolicy', {
            policyName: this.RESOURCE_PREFIX + '-SHARR_Custom_Action',
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
            description: 'Lambda role to allow creation of Security Hub Custom Actions',
            roleName: this.RESOURCE_PREFIX + '_Custom_Action',
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
            functionName: this.RESOURCE_PREFIX + '-SHARR-CustomAction',
            handler: 'createCustomAction.lambda_handler',
            runtime: lambda.Runtime.PYTHON_3_8,
            description: 'Custom resource to create an action target in Security Hub',
            code: lambda.Code.fromBucket(
                SolutionsBucket,
                this.SOLUTION_TMN + '/' + this.SOLUTION_VERSION + '/lambda/createCustomAction.py.zip'
            ),
            environment: {
                log_level: 'info',
                sendAnonymousMetrics: mapping.findInMap("sendAnonymousMetrics", "data")
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

        //=========================================================================
        // SERVICE CATALOG ADMIN
        //
        //-------------------------------------------------------------------------
        // Service Catalog Admin Role
        // Default role allowing administration of Playbook products
        const sharrCatAdminPolicy = new iam.ManagedPolicy(this, 'SHARRCatalogAdminPolicy', {
            managedPolicyName: this.RESOURCE_PREFIX + '-SHARR_Catalog_Admin',
            statements: [
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'cloudformation:CreateStack',
                        'cloudformation:DeleteStack',
                        'cloudformation:DescribeStackEvents',
                        'cloudformation:DescribeStacks',
                        'cloudformation:SetStackPolicy',
                        'cloudformation:UpdateStack',
                        'cloudformation:CreateChangeSet',
                        'cloudformation:DescribeChangeSet',
                        'cloudformation:ExecuteChangeSet',
                        'cloudformation:ListChangeSets',
                        'cloudformation:DeleteChangeSet',
                        'cloudformation:ListStackResources',
                        'cloudformation:TagResource',
                        'cloudformation:CreateStackSet',
                        'cloudformation:CreateStackInstances',
                        'cloudformation:UpdateStackSet',
                        'cloudformation:UpdateStackInstances',
                        'cloudformation:DeleteStackSet',
                        'cloudformation:DeleteStackInstances',
                        'cloudformation:DescribeStackSet',
                        'cloudformation:DescribeStackInstance',
                        'cloudformation:DescribeStackSetOperation',
                        'cloudformation:ListStackInstances',
                        'cloudformation:ListStackSetOperations',
                        'cloudformation:ListStackSetOperationResults',
                    ],
                    resources: [
                        'arn:aws:cloudformation:*:*:stack/SC-*',
                        'arn:aws:cloudformation:*:*:stack/StackSet-SC-*',
                        'arn:aws:cloudformation:*:*:changeSet/SC-*',
                        'arn:aws:cloudformation:*:*:stackset/SC-*'
                    ]
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'cloudformation:CreateStack',
                        'servicecatalog:*'
                    ],
                    resources: ['*']
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'cloudformation:CreateUploadBucket',
                        'cloudformation:GetTemplateSummary',
                        'cloudformation:ValidateTemplate',
                        'iam:GetGroup',
                        'iam:GetRole',
                        'iam:GetUser',
                        'iam:ListGroups',
                        'iam:ListRoles',
                        'iam:ListUsers',
                        'ssm:DescribeDocument',
                        'ssm:GetAutomationExecution',
                        'ssm:ListDocuments',
                        'ssm:ListDocumentVersions',
                        'config:DescribeConfigurationRecorders',
                        'config:DescribeConfigurationRecorderStatus'
                    ],
                    resources: ['*']
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'servicecatalog:DescribeProvisionedProduct',
                        'servicecatalog:DescribeRecord',
                        'servicecatalog:ListRecordHistory',
                        'servicecatalog:ListStackInstancesForProvisionedProduct',
                        'servicecatalog:ScanProvisionedProducts',
                        'servicecatalog:TerminateProvisionedProduct',
                        'servicecatalog:UpdateProvisionedProduct',
                        'servicecatalog:SearchProvisionedProducts',
                        'servicecatalog:CreateProvisionedProductPlan',
                        'servicecatalog:DescribeProvisionedProductPlan',
                        'servicecatalog:ExecuteProvisionedProductPlan',
                        'servicecatalog:DeleteProvisionedProductPlan',
                        'servicecatalog:ListProvisionedProductPlans',
                        'servicecatalog:ListServiceActionsForProvisioningArtifact',
                        'servicecatalog:ExecuteProvisionedProductServiceAction',
                        'servicecatalog:DescribeServiceActionExecutionParameters'
                    ],
                    resources: ['*']
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'iam:CreateRole'
                    ],
                    resources: ['arn:aws:iam::' + this.account + ':role/SO0111*']
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'lambda:InvokeFunction'
                    ],
                    resources: [createCustomAction.functionArn]
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'iam:PassRole'
                    ],
                    resources: ['*'],
                    conditions: {
                        StringEquals: {
                            'iam:PassedToService': 'servicecatalog.amazonaws.com'
                        }
                    }
                })
            ]
        });

        const catAdminPolicyResource = sharrCatAdminPolicy.node.findChild('Resource') as iam.CfnManagedPolicy;

        catAdminPolicyResource.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'F40',
                    reason: 'Resource * is necessary for passrole permissions with Service Catalog. Service Catalog controls access its resources through IAM role, group, and user association.'
                },{
                    id: 'F5',
                    reason: 'Action * is necessary for admin permissions within Service Catalog. Service Catalog controls access its resources through IAM role, group, and user association.'
                },{
                    id: 'W13',
                    reason: 'Resource * is necessary for permissions with Service Catalog. Service Catalog controls access its resources through IAM role, group, and user association.'
                },{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide easy integration with playbook templates'
                }]
            }
        };

        //-------------------------------------------------------------------------
        // Group
        const sharrCatAdminGroup = new iam.Group(this, 'SHARRCatAdminGroup', {
            groupName: this.RESOURCE_PREFIX + '-SHARR_Catalog_Admin',
            managedPolicies: [
                sharrCatAdminPolicy
            ]
        })

        const catAdminGroupResource = sharrCatAdminGroup.node.findChild('Resource') as iam.CfnGroup;

        catAdminGroupResource.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide easy integration with playbook templates'
                }]
            }
        };

        //=========================================================================
        // SERVICE CATALOG USER
        //
        //-------------------------------------------------------------------------
        // Service Catalog User Role
        // Default role allowing administration of Playbook products
        const sharrCatUserPolicy = new iam.ManagedPolicy(this, 'SHARR-Catalog-User-Policy', {
            managedPolicyName: this.RESOURCE_PREFIX + '-SHARR_Catalog_User',
            statements: [
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'cloudformation:CreateStack',
                        'cloudformation:DeleteStack',
                        'cloudformation:DescribeStackEvents',
                        'cloudformation:DescribeStacks',
                        'cloudformation:SetStackPolicy',
                        'cloudformation:ValidateTemplate',
                        'cloudformation:UpdateStack',
                        'cloudformation:CreateChangeSet',
                        'cloudformation:DescribeChangeSet',
                        'cloudformation:ExecuteChangeSet',
                        'cloudformation:ListChangeSets',
                        'cloudformation:DeleteChangeSet',
                        'cloudformation:TagResource',
                        'cloudformation:CreateStackSet',
                        'cloudformation:CreateStackInstances',
                        'cloudformation:UpdateStackSet',
                        'cloudformation:UpdateStackInstances',
                        'cloudformation:DeleteStackSet',
                        'cloudformation:DeleteStackInstances',
                        'cloudformation:DescribeStackSet',
                        'cloudformation:DescribeStackInstance',
                        'cloudformation:DescribeStackSetOperation',
                        'cloudformation:ListStackInstances',
                        'cloudformation:ListStackResources',
                        'cloudformation:ListStackSetOperations',
                        'cloudformation:ListStackSetOperationResults'
                    ],
                    resources: [
                        'arn:aws:cloudformation:*:*:stack/SC-*',
                        'arn:aws:cloudformation:*:*:stack/StackSet-SC-*',
                        'arn:aws:cloudformation:*:*:changeSet/SC-*',
                        'arn:aws:cloudformation:*:*:stackset/SC-*'
                    ]
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'cloudformation:GetTemplateSummary',
                        'servicecatalog:DescribeProduct',
                        'servicecatalog:DescribeProductView',
                        'servicecatalog:DescribeProvisioningParameters',
                        'servicecatalog:ListLaunchPaths',
                        'servicecatalog:ProvisionProduct',
                        'servicecatalog:SearchProducts',
                        'ssm:DescribeDocument',
                        'ssm:GetAutomationExecution',
                        'config:DescribeConfigurationRecorders',
                        'config:DescribeConfigurationRecorderStatus'
                    ],
                    resources: ['*']
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'servicecatalog:DescribeProvisionedProduct',
                        'servicecatalog:DescribeRecord',
                        'servicecatalog:ListRecordHistory',
                        'servicecatalog:ListStackInstancesForProvisionedProduct',
                        'servicecatalog:ScanProvisionedProducts',
                        'servicecatalog:TerminateProvisionedProduct',
                        'servicecatalog:UpdateProvisionedProduct',
                        'servicecatalog:SearchProvisionedProducts',
                        'servicecatalog:CreateProvisionedProductPlan',
                        'servicecatalog:DescribeProvisionedProductPlan',
                        'servicecatalog:ExecuteProvisionedProductPlan',
                        'servicecatalog:DeleteProvisionedProductPlan',
                        'servicecatalog:ListProvisionedProductPlans',
                        'servicecatalog:ListServiceActionsForProvisioningArtifact',
                        'servicecatalog:ExecuteProvisionedProductServiceAction',
                        'servicecatalog:DescribeServiceActionExecutionParameters'
                    ],
                    resources: [
                        'arn:aws:catalog:' + this.region + ':' + this.account + ':portfolio/' + solPortfolio.ref,
                        'arn:aws:catalog:*:*:product/*'
                    ]
                }),
                new iam.PolicyStatement({
                    effect: iam.Effect.ALLOW,
                    actions: [
                        'iam:CreateRole'
                    ],
                    resources: ['arn:aws:iam::' + this.account + ':role/SO0111*']
                }),
            ]
        });

        const catUserPolicyResource = sharrCatUserPolicy.node.findChild('Resource') as iam.CfnManagedPolicy;

        catUserPolicyResource.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W13',
                    reason: 'Resource * is necessary for permissions with Service Catalog. Service Catalog controls access its resources through IAM role, group, and user association.'
                },{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide easy integration with playbook templates'
                }]
            }
        };


        //-------------------------------------------------------------------------
        // Group
        const sharrCatUserGroup = new iam.Group(this, 'SHARRCatUserGroup', {
            groupName: this.RESOURCE_PREFIX + '-SHARR_Catalog_User',
            managedPolicies: [
                sharrCatUserPolicy
            ]
        })

        const catUserGroupResource = sharrCatUserGroup.node.findChild('Resource') as iam.CfnGroup;

        catUserGroupResource.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide easy integration with playbook templates'
                }]
            }
        };

        //-------------------------------------------------------------------------
        // Associate roles with portfolio
        //
        new sc.CfnPortfolioPrincipalAssociation(this, 'PortfolioUserAccess', {
            portfolioId: solPortfolio.ref,
            principalArn: sharrCatUserGroup.groupArn,
            principalType: 'IAM'
        })

        new sc.CfnPortfolioPrincipalAssociation(this, 'PortfolioAdminAccess', {
            portfolioId: solPortfolio.ref,
            principalArn: sharrCatAdminGroup.groupArn,
            principalType: 'IAM'
        })

        //-------------------------------------------------------------------------
        // Loop through all of the Playbooks and create a Product for each SET of playbooks
        //
        const PB_DIR = '../playbooks';
        var ignore = ['.DS_Store', 'core', 'python_lib', 'python_tests', '.pytest_cache'];
        fs.readdir(PB_DIR, (err, items) => {
            items.forEach(file => {
                if (!ignore.includes(file)) {
                    // template is in ./template -> global *.template
                    // lambda source is in ./source -> regional *.py.zip
                    let description = 'This is the default description';
                    // description.txt takes precedence. Used when author wants more than the one-line description
                    if (fs.existsSync(PB_DIR + '/' + file + '/description.txt')) {
                        description = fs.readFileSync(PB_DIR + '/' + file + '/description.txt', 'utf8');
                    }
                    let support_description = 'This is the default description';
                    // support.txt takes precedence. Used when author wants more than the one-line description
                    if (fs.existsSync(PB_DIR + '/' + file + '/support.txt')) {
                        support_description = fs.readFileSync(PB_DIR + '/' + file + '/support.txt', 'utf8');
                    }
                    let versionDesc = 'This is the default version description';
                    if (fs.existsSync(PB_DIR + '/' + file + '/version_description.txt')) {
                        versionDesc = fs.readFileSync(PB_DIR + '/' + file + '/version_description.txt', 'utf8');
                    }
                    let playbook = new sc.CfnCloudFormationProduct(this, 'playbook-' + file, {
                        name: file,
                        owner: 'AWS Solutions Development',
                        provisioningArtifactParameters: [
                            {
                                'info': {
                                    'LoadTemplateFromURL': 'https://' + this.SOLUTION_BUCKET +
                                        '-reference.s3.amazonaws.com/' + this.SOLUTION_TMN + '/' +
                                        this.SOLUTION_VERSION + '/playbooks/' + file + '.template'
                                },
                                'name': this.SOLUTION_VERSION,
                                'description': versionDesc
                            }
                        ],
                        distributor: 'AWS',
                        description: description,
                        supportDescription: '[' + this.SOLUTION_NAME + ' ' + this.SOLUTION_VERSION + '] ' +
                            support_description,
                        supportUrl: 'https://aws.amazon.com/solutions/'
                    })
                    new sc.CfnPortfolioProductAssociation(this, 'PortfolioAssoc-' + file, {
                        portfolioId: solPortfolio.ref,
                        productId: playbook.ref
                    })
                };
            });
        });
    }
}
