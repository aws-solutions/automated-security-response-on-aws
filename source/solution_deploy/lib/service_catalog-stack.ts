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

import * as cdk from '@aws-cdk/core';
import * as sc from '@aws-cdk/aws-servicecatalog';
import * as iam from '@aws-cdk/aws-iam';
import * as fs from 'fs';

export interface SHARRStackProps extends cdk.StackProps {
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionTMN: string;
    solutionName: string;
}

export class ServiceCatalogStack extends cdk.Stack {

  portfolioDescription = ''
  readonly solutionProvider = 'AWS Solution Development';
  SEND_ANONYMOUS_DATA = 'Yes'

  constructor(scope: cdk.App, id: string, props: SHARRStackProps) {

    super(scope, id, props);

    const RESOURCE_PREFIX = props.solutionId; // prefix on every resource name

    this.portfolioDescription = 'Portfolio of available ' + props.solutionName +
        ' Playbooks. See https://aws.amazon.com/solutions/implementations/aws-security-hub-automated-response-and-remediation/';

    // Create Custom Action function arn
    // ----------------------------------
    const paramCreateCustomActionArn = new cdk.CfnParameter(this, 'CreateCustomActionArn', {
        description: "ARN of the CreateCustomAction lambda from the parent stack.",
        type: "String"
    });
    //-------------------------------------------------------------------------
    // Configure ServiceCatalog Portfolio
    //
    const solPortfolio = new sc.CfnPortfolio(this, 'SC-Playbooks', {
        displayName: 'Security Hub Playbooks (' + RESOURCE_PREFIX + ')',
        providerName: this.solutionProvider,
        description: this.portfolioDescription
    });

    const mapping = new cdk.CfnMapping(this, 'mappings');
    mapping.setValue("sendAnonymousMetrics", "data", this.SEND_ANONYMOUS_DATA)

    //=========================================================================
    // SERVICE CATALOG ADMIN
    //
    //-------------------------------------------------------------------------
    // Service Catalog Admin Role
    // Default role allowing administration of Playbook products
    const sharrCatAdminPolicy = new iam.ManagedPolicy(this, 'SHARRCatalogAdminPolicy', {
        // managedPolicyName: RESOURCE_PREFIX + '-SHARR_Catalog_Admin',
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
                    'arn:' + this.partition + ':cloudformation:*:*:stack/SC-*',
                    'arn:' + this.partition + ':cloudformation:*:*:stack/StackSet-SC-*',
                    'arn:' + this.partition + ':cloudformation:*:*:changeSet/SC-*',
                    'arn:' + this.partition + ':cloudformation:*:*:stackset/SC-*'
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
                resources: ['arn:' + this.partition + ':iam::' + this.account + ':role/SO0111*']
            }),
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                    'lambda:InvokeFunction'
                ],
                resources: [paramCreateCustomActionArn.valueAsString]
            }),
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                    'iam:PassRole'
                ],
                resources: ['*'],
                conditions: {
                    StringEquals: {
                        'iam:PassedToService': `servicecatalog.${this.urlSuffix}`
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
        groupName: RESOURCE_PREFIX + '-SHARR_Catalog_Admin_' + this.region,
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
        // managedPolicyName: RESOURCE_PREFIX + '-SHARR_Catalog_User',
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
                    'arn:' + this.partition + ':cloudformation:*:*:stack/SC-*',
                    'arn:' + this.partition + ':cloudformation:*:*:stack/StackSet-SC-*',
                    'arn:' + this.partition + ':cloudformation:*:*:changeSet/SC-*',
                    'arn:' + this.partition + ':cloudformation:*:*:stackset/SC-*'
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
                    'arn:' + this.partition + ':catalog:' + this.region + ':' + this.account + ':portfolio/' + solPortfolio.ref,
                    'arn:' + this.partition + ':catalog:*:*:product/*'
                ]
            }),
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                    'iam:CreateRole'
                ],
                resources: ['arn:' + this.partition + ':iam::' + this.account + ':role/SO0111*']
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
        groupName: RESOURCE_PREFIX + '-SHARR_Catalog_User_' + this.region,
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
                                'LoadTemplateFromURL': 'https://' + props.solutionDistBucket +
                                    '-reference.s3.amazonaws.com/' + props.solutionTMN + '/' +
                                    props.solutionVersion + '/playbooks/' + file + 'Stack.template'
                            },
                            'name': props.solutionVersion,
                            'description': versionDesc
                        }
                    ],
                    distributor: 'AWS',
                    description: description,
                    supportDescription: '[' + props.solutionName + ' ' + props.solutionVersion + '] ' +
                        support_description,
                    supportUrl: 'https://aws.amazon.com/solutions/'
                })
                new sc.CfnPortfolioProductAssociation(this, 'PortfolioAssoc-' + file, {
                    portfolioId: solPortfolio.ref,
                    productId: playbook.ref
                })
            }
        })
    })
  }
}
