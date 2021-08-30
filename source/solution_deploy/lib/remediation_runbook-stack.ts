#!/usr/bin/env node
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

//
// Remediation Runbook Stack - installs non standard-specific remediation 
// runbooks that are used by one or more standards
//
import * as cdk from '@aws-cdk/core';
import { 
    PolicyStatement, 
    PolicyDocument,
    Effect, 
    Role, 
    Policy, 
    ServicePrincipal, 
    CfnPolicy,
    CfnRole
} from '@aws-cdk/aws-iam';
// import { Key } from '@aws-cdk/aws-kms';
// import { StringParameter } from '@aws-cdk/aws-ssm';
import { SsmRemediationRunbook, SsmRole } from '../../lib/ssmplaybook';
import { AdminAccountParm } from '../../lib/admin_account_parm-construct';
import { Rds6EnhancedMonitoringRole } from '../../remediation_runbooks/rds6-remediation-resources';

export interface StackProps {
    description: string;
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    ssmdocs?: string;
}

export class RemediationRunbookStack extends cdk.Stack {

  constructor(scope: cdk.App, id: string, props: StackProps) {
    super(scope, id, props);
    let ssmdocs = ''
    if (props.ssmdocs == undefined) {
        ssmdocs = '../remediation_runbooks'
    } else {
        ssmdocs = props.ssmdocs
    }

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/,''); // prefix on every resource name

    const adminAccount = new AdminAccountParm(this, 'AdminAccountParameter', {
        solutionId: props.solutionId
    })
    // const adminRoleName = `${RESOURCE_PREFIX}-SHARR-Orchestrator-Admin_${this.region}`
    const remediationRoleNameBase = `${RESOURCE_PREFIX}-`
    
    //-----------------------
    // CreateCloudTrailMultiRegionTrail
    //
    {
        const remediationName = 'CreateCloudTrailMultiRegionTrail'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const cloudtrailPerms = new PolicyStatement();
        cloudtrailPerms.addActions(
            "cloudtrail:CreateTrail",
            "cloudtrail:UpdateTrail",
            "cloudtrail:StartLogging"
        )
        cloudtrailPerms.effect = Effect.ALLOW
        cloudtrailPerms.addResources("*");
        inlinePolicy.addStatements(cloudtrailPerms)

        const s3Perms = new PolicyStatement();
        s3Perms.addActions(
            "s3:CreateBucket",
            "s3:PutEncryptionConfiguration",
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketLogging",
            "s3:PutBucketAcl",
            "s3:PutBucketPolicy"
        )
        s3Perms.effect = Effect.ALLOW
        s3Perms.addResources(
            `arn:${this.partition}:s3:::so0111-*`
        );
        inlinePolicy.addStatements(s3Perms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            // adminRoleName: adminRoleName,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation.'
                },{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide integration in cross-account permissions.'
                }]
            }
        }
    }
    //-----------------------
    // EnableAutoScalingGroupELBHealthCheck
    //
    {
        const remediationName = 'EnableAutoScalingGroupELBHealthCheck'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const asPerms = new PolicyStatement();
        asPerms.addActions(
            "autoscaling:UpdateAutoScalingGroup",
            "autoscaling:DescribeAutoScalingGroups"
        )
        asPerms.effect = Effect.ALLOW
        asPerms.addResources("*");
        inlinePolicy.addStatements(asPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            // adminRoleName: adminRoleName,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* ASG.'
                }]
            }
        }
    }

    //-----------------------
    // EnableAWSConfig
    //
    {
        const remediationName = 'EnableAWSConfig'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        {
            var iamPerms = new PolicyStatement();
            iamPerms.addActions(
                "iam:GetRole",
                "iam:PassRole"
            )
            iamPerms.effect = Effect.ALLOW
            iamPerms.addResources(
                `arn:${this.partition}:iam::${this.account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig`,
                `arn:${this.partition}:iam::${this.account}:role/SO0111-CreateAccessLoggingBucket_*`
            );
            inlinePolicy.addStatements(iamPerms)
        }
        {
            var snsPerms = new PolicyStatement();
            snsPerms.addActions(
                "sns:CreateTopic",
                "sns:SetTopicAttributes"
            )
            snsPerms.effect = Effect.ALLOW
            snsPerms.addResources(
                `arn:${this.partition}:sns:${this.region}:${this.account}:SO0111-SHARR-AWSConfigNotification`
            );
            inlinePolicy.addStatements(snsPerms)
        }
        {
            var ssmPerms = new PolicyStatement();
            ssmPerms.addActions(
                "ssm:StartAutomationExecution"
            )
            ssmPerms.effect = Effect.ALLOW
            ssmPerms.addResources(
                `arn:${this.partition}:ssm:${this.region}:${this.account}:automation-definition/SHARR-CreateAccessLoggingBucket:*`
            );
            inlinePolicy.addStatements(ssmPerms)
        }
        {
            var configPerms = new PolicyStatement();
            configPerms.addActions(
                "ssm:GetAutomationExecution",
                "config:PutConfigurationRecorder",
                "config:PutDeliveryChannel",
                "config:DescribeConfigurationRecorders",
                "config:StartConfigurationRecorder"
            )
            configPerms.effect = Effect.ALLOW
            configPerms.addResources(
                `*`
            );
            inlinePolicy.addStatements(configPerms)
        }

        const s3Perms = new PolicyStatement();
        s3Perms.addActions(
            "s3:CreateBucket",
            "s3:PutEncryptionConfiguration",
            "s3:PutBucketPublicAccessBlock",
            "s3:PutBucketLogging",
            "s3:PutBucketAcl",
            "s3:PutBucketPolicy"
        )
        s3Perms.effect = Effect.ALLOW
        s3Perms.addResources(
            `arn:${this.partition}:s3:::so0111-*`
        );
        inlinePolicy.addStatements(s3Perms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            // adminRoleName: adminRoleName,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }
    
    //-----------------------
    // EnableCloudTrailToCloudWatchLogging
    //
    {
        const remediationName = 'EnableCloudTrailToCloudWatchLogging'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        // Role for CT->CW logging
        const ctcw_remediation_policy_statement_1 = new PolicyStatement()
        ctcw_remediation_policy_statement_1.addActions("logs:CreateLogStream")
        ctcw_remediation_policy_statement_1.effect = Effect.ALLOW
        ctcw_remediation_policy_statement_1.addResources(
            "arn:" + this.partition + ":logs:*:*:log-group:*"
        )

        const ctcw_remediation_policy_statement_2 = new PolicyStatement()
        ctcw_remediation_policy_statement_2.addActions("logs:PutLogEvents")
        ctcw_remediation_policy_statement_2.effect = Effect.ALLOW
        ctcw_remediation_policy_statement_2.addResources(
            "arn:" + this.partition + ":logs:*:*:log-group:*:log-stream:*"
        )

        const ctcw_remediation_policy_doc = new PolicyDocument()
        ctcw_remediation_policy_doc.addStatements(ctcw_remediation_policy_statement_1) 
        ctcw_remediation_policy_doc.addStatements(ctcw_remediation_policy_statement_2) 

        const ctcw_remediation_role = new Role(this, 'ctcwremediationrole', {
            assumedBy: new ServicePrincipal(`cloudtrail.${this.urlSuffix}`),
            inlinePolicies: {
                'default_lambdaPolicy': ctcw_remediation_policy_doc
            },
            roleName: RESOURCE_PREFIX + '-CloudTrailToCloudWatchLogs_' + this.region
        });
        {
            let childToMod = ctcw_remediation_role.node.findChild('Resource') as CfnRole;
            childToMod.cfnOptions.metadata = {
                cfn_nag: {
                    rules_to_suppress: [{
                        id: 'W28',
                        reason: 'Static names chosen intentionally to provide integration in cross-account permissions'
                    }]
                }
            }
        }   
        {
            const ctperms = new PolicyStatement();
            ctperms.addActions("cloudtrail:UpdateTrail")

            ctperms.effect = Effect.ALLOW
            ctperms.addResources(
                "arn:" + this.partition + ":cloudtrail:*:" + this.account + ":trail/*"
            );
            inlinePolicy.addStatements(ctperms)
        }
        {
            const ctcwiam = new PolicyStatement();
            ctcwiam.addActions(
                "iam:PassRole"
            )
            ctcwiam.addResources(
                ctcw_remediation_role.roleArn
            );
            inlinePolicy.addStatements(ctcwiam)
        }
        {
            const ctcwlogs = new PolicyStatement();
            ctcwlogs.addActions(
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups"
            )
            ctcwlogs.effect = Effect.ALLOW
            ctcwlogs.addResources("*");
            inlinePolicy.addStatements(ctcwlogs)
        }

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR ' + remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
        {
            let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
            childToMod.cfnOptions.metadata = {
                cfn_nag: {
                    rules_to_suppress: [{
                        id: 'W12',
                        reason: 'Resource * is required for to allow creation and description of any log group'
                    },{
                        id: 'W28',
                        reason: 'Static resource names are required to enable cross-account functionality'
                    }]
                }
            }
        }
    }
    //-----------------------
    // EnableCloudTrailEncryption
    //
    {
        const remediationName = 'EnableCloudTrailEncryption'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const cloudtrailPerms = new PolicyStatement();
        cloudtrailPerms.addActions("cloudtrail:UpdateTrail")
        cloudtrailPerms.effect = Effect.ALLOW
        cloudtrailPerms.addResources("*");
        inlinePolicy.addStatements(cloudtrailPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation.'
                },{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide integration in cross-account permissions.'
                }]
            }
        }
    }

    //-----------------------
    // EnableVPCFlowLogs
    //
    {
        const remediationName = 'EnableVPCFlowLogs'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        {
            let remediationPerms = new PolicyStatement();
            remediationPerms.addActions(
                "ec2:CreateFlowLogs"
            )
            remediationPerms.effect = Effect.ALLOW
            remediationPerms.addResources(
                `arn:${this.partition}:ec2:*:${this.account}:vpc/*`,
                `arn:${this.partition}:ec2:*:${this.account}:vpc-flow-log/*`
            );
            inlinePolicy.addStatements(remediationPerms)
        }

        {
            let iamPerms = new PolicyStatement()
            iamPerms.addActions(
                "iam:PassRole"
            )
            iamPerms.effect = Effect.ALLOW
            iamPerms.addResources(
                `arn:${this.partition}:iam::${this.account}:role/${RESOURCE_PREFIX}-${remediationName}-remediationRole_${this.region}`
            );
            inlinePolicy.addStatements(iamPerms)
        }
        
        {
            let validationPerms = new PolicyStatement()
            validationPerms.addActions(
                "ec2:DescribeFlowLogs",
                "logs:CreateLogGroup",
                "logs:DescribeLogGroups"
            )
            validationPerms.effect = Effect.ALLOW
            validationPerms.addResources("*");
            inlinePolicy.addStatements(validationPerms)
        }

        // Remediation Role
        const remediation_policy = new PolicyStatement()
        remediation_policy.effect = Effect.ALLOW
        remediation_policy.addActions(
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
            "logs:PutLogEvents"
        )
        remediation_policy.addResources("*")

        const remediation_doc = new PolicyDocument()
        remediation_doc.addStatements(remediation_policy)

        const remediation_role = new Role(this, 'EnableVPCFlowLogs-remediationrole', {
            assumedBy: new ServicePrincipal('vpc-flow-logs.amazonaws.com'),
            inlinePolicies: {
                'default_lambdaPolicy': remediation_doc
            },
            roleName: `${RESOURCE_PREFIX}-EnableVPCFlowLogs-remediationRole_${this.region}`
        });

        const roleResource = remediation_role.node.findChild('Resource') as CfnRole;

        roleResource.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W11',
                    reason: 'Resource * is required due to the administrative nature of the solution.'
                },{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide integration in cross-account permissions'
                }]
            }
        };

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resources.'
                }]
            }
        }
    }

    //-----------------------
    // CreateAccessLoggingBucket
    //
    {
        const remediationName = 'CreateAccessLoggingBucket'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const s3Perms = new PolicyStatement();
        s3Perms.addActions(
            "s3:CreateBucket",
            "s3:PutEncryptionConfiguration",
            "s3:PutBucketAcl"
        )
        s3Perms.effect = Effect.ALLOW
        s3Perms.addResources("*");
    
        inlinePolicy.addStatements(s3Perms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resources.'
                }]
            }
        }
    }

    //-----------------------
    // MakeEBSSnapshotsPrivate
    //
    {
        const remediationName = 'MakeEBSSnapshotsPrivate'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const ec2Perms = new PolicyStatement();
        ec2Perms.addActions(
            "ec2:ModifySnapshotAttribute",
            "ec2:DescribeSnapshots"
            )
        ec2Perms.effect = Effect.ALLOW
        ec2Perms.addResources("*");
        inlinePolicy.addStatements(ec2Perms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* snapshot.'
                }]
            }
        }
    }
    
    //-----------------------
    // MakeRDSSnapshotPrivate
    //
    {
        const remediationName = 'MakeRDSSnapshotPrivate'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const remediationPerms = new PolicyStatement();
        remediationPerms.addActions(
            "rds:ModifyDBSnapshotAttribute",
            "rds:ModifyDBClusterSnapshotAttribute"
            )
        remediationPerms.effect = Effect.ALLOW
        remediationPerms.addResources("*");
        inlinePolicy.addStatements(remediationPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* snapshot.'
                }]
            }
        }
    }

    //-----------------------
    // RemoveLambdaPublicAccess
    //
    {
        const remediationName = 'RemoveLambdaPublicAccess'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const lambdaPerms = new PolicyStatement();
        lambdaPerms.addActions(
            "lambda:GetPolicy",
            "lambda:RemovePermission"
        )
        lambdaPerms.effect = Effect.ALLOW
        lambdaPerms.addResources('*')
        inlinePolicy.addStatements(lambdaPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for any resource.'
                }]
            }
        }
    }
    
    //=========================================================================
    // The following are permissions only for use with AWS-owned documents that
    //   are available to GovCloud and China partition customers.
    //=========================================================================
    //-----------------------
    // AWS-ConfigureS3BucketLogging
    //
    {
        const remediationName = 'ConfigureS3BucketLogging'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const s3Perms = new PolicyStatement();
        s3Perms.addActions(
            "s3:PutBucketLogging",
            "s3:CreateBucket",
            "s3:PutEncryptionConfiguration"
        )
        s3Perms.addActions("s3:PutBucketAcl")
        s3Perms.effect = Effect.ALLOW
        s3Perms.addResources("*");

        inlinePolicy.addStatements(s3Perms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            // adminRoleName: adminRoleName,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }
    //-----------------------------------------
    // AWS-DisablePublicAccessForSecurityGroup
    //
    {
        const remediationName = 'DisablePublicAccessForSecurityGroup'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const remediationPermsEc2 = new PolicyStatement();
            remediationPermsEc2.addActions(
                "ec2:DescribeSecurityGroupReferences",
                "ec2:DescribeSecurityGroups",
                "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
                "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
                "ec2:RevokeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupEgress"
            )
            remediationPermsEc2.effect = Effect.ALLOW
            remediationPermsEc2.addResources("*");
        inlinePolicy.addStatements(remediationPermsEc2)
        
        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }
    //=========================================================================
    // The following runbooks are copied from AWS-owned documents to make them
    //   available to GovCloud and China partition customers. The 
    //   SsmRemediationRunbook should be removed when they become available in 
    //   aws-cn and aws-us-gov. The SsmRole must be retained.
    //=========================================================================
    //-----------------------
    // AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock
    //
    {
        const remediationName = 'ConfigureS3BucketPublicAccessBlock'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const remediationPolicy = new PolicyStatement();
        remediationPolicy.addActions(
            "s3:PutBucketPublicAccessBlock",
            "s3:GetBucketPublicAccessBlock"
        );
        remediationPolicy.effect = Effect.ALLOW
        remediationPolicy.addResources("*")
        inlinePolicy.addStatements(remediationPolicy)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }
    //-----------------------
    // AWSConfigRemediation-ConfigureS3PublicAccessBlock
    //
    {
        const remediationName = 'ConfigureS3PublicAccessBlock'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const remediationPolicy = new PolicyStatement();
        remediationPolicy.addActions(
            "s3:PutAccountPublicAccessBlock",
            "s3:GetAccountPublicAccessBlock"
        );
        remediationPolicy.effect = Effect.ALLOW
        remediationPolicy.addResources("*")
        inlinePolicy.addStatements(remediationPolicy)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }
    //-----------------------
    // AWSConfigRemediation-EnableCloudTrailLogFileValidation
    //
    {
        const remediationName = 'EnableCloudTrailLogFileValidation'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const remediationPolicy = new PolicyStatement();
        remediationPolicy.addActions(
            "cloudtrail:UpdateTrail",
            "cloudtrail:GetTrail"
        )
        remediationPolicy.effect = Effect.ALLOW
        remediationPolicy.addResources(
            "arn:" + this.partition + ":cloudtrail:*:" + this.account + ":trail/*"
        );
        inlinePolicy.addStatements(remediationPolicy)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
    }

    //-----------------------
    // AWSConfigRemediation-EnableEbsEncryptionByDefault
    //
    {
        const remediationName = 'EnableEbsEncryptionByDefault'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const ec2Perms = new PolicyStatement();
        ec2Perms.addActions(
            "ec2:EnableEBSEncryptionByDefault",
            "ec2:GetEbsEncryptionByDefault"
        )
        ec2Perms.effect = Effect.ALLOW
        ec2Perms.addResources("*");
        inlinePolicy.addStatements(ec2Perms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            // adminRoleName: adminRoleName,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }

    //-----------------------
    // AWSConfigRemediation-EnableEnhancedMonitoringOnRDSInstance
    //
    {
        const remediationName = 'EnableEnhancedMonitoringOnRDSInstance'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        {
            let iamPerms = new PolicyStatement()
            iamPerms.addActions(
                "iam:GetRole",
                "iam:PassRole"
            )
            iamPerms.effect = Effect.ALLOW
            iamPerms.addResources(
                `arn:${this.partition}:iam::${this.account}:role/${RESOURCE_PREFIX}-RDSMonitoring-remediationRole_${this.region}`
            );
            inlinePolicy.addStatements(iamPerms)
        }
        {
            const rdsPerms = new PolicyStatement();
            rdsPerms.addActions(
                "rds:DescribeDBInstances",
                "rds:ModifyDBInstance"
            )
            rdsPerms.effect = Effect.ALLOW
            rdsPerms.addResources("*");
            inlinePolicy.addStatements(rdsPerms)
        }

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* RDS database.'
                }]
            }
        }

        new Rds6EnhancedMonitoringRole(this, 'Rds6EnhancedMonitoringRole',  {
            roleName: `${RESOURCE_PREFIX}-RDSMonitoring-remediationRole_${this.region}`
        })
    }
    //-----------------------
    // AWSConfigRemediation-EnableKeyRotation
    //
    {
        const remediationName = 'EnableKeyRotation'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const remediationPerms = new PolicyStatement();
        remediationPerms.addActions(
            "kms:EnableKeyRotation",
            "kms:GetKeyRotationStatus"
        )
        remediationPerms.effect = Effect.ALLOW
        remediationPerms.addResources("*");
        inlinePolicy.addStatements(remediationPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* resource.'
                }]
            }
        }
    }

    //-----------------------
    // AWSConfigRemediation-EnableRDSClusterDeletionProtection
    //
    {
        const remediationName = 'EnableRDSClusterDeletionProtection'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);

        const iamPerms = new PolicyStatement();
        iamPerms.addActions("iam:GetRole")
        iamPerms.effect = Effect.ALLOW
        iamPerms.addResources(
            'arn:' + this.partition + ':iam::' + this.account + ':role/RDSEnhancedMonitoringRole'
        );
        inlinePolicy.addStatements(iamPerms)

        const configPerms = new PolicyStatement();
        configPerms.addActions("config:GetResourceConfigHistory")
        configPerms.effect = Effect.ALLOW
        configPerms.addResources("*");
        inlinePolicy.addStatements(configPerms)

        const rdsPerms = new PolicyStatement();
        rdsPerms.addActions(
            "rds:DescribeDBClusters",
            "rds:ModifyDBCluster"
        )
        rdsPerms.effect = Effect.ALLOW
        rdsPerms.addResources("*");
        inlinePolicy.addStatements(rdsPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* RDS database.'
                }]
            }
        }
    }
    //-----------------------
    // AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules
    //
    {
        const remediationName = 'RemoveVPCDefaultSecurityGroupRules'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        
        const remediationPolicy1 = new PolicyStatement();
        remediationPolicy1.addActions(
            "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
            "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress"
            )
        remediationPolicy1.effect = Effect.ALLOW
        remediationPolicy1.addResources("arn:" + this.partition + ":ec2:*:"+this.account+":security-group/*");

        const remediationPolicy2 = new PolicyStatement();
        remediationPolicy2.addActions(
            "ec2:DescribeSecurityGroupReferences",
            "ec2:DescribeSecurityGroups"
            )
        remediationPolicy2.effect = Effect.ALLOW
        remediationPolicy2.addResources("*")

        inlinePolicy.addStatements(remediationPolicy1, remediationPolicy2)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for any resource.'
                },{
                    id: 'W28',
                    reason: 'Static names chosen intentionally to provide integration in cross-account permissions'
                }]
            }
        }
    }
    //-----------------------
    // AWSConfigRemediation-RevokeUnusedIAMUserCredentials
    //
    {
        const remediationName = 'RevokeUnusedIAMUserCredentials'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        const remediationPolicy = new PolicyStatement();
        remediationPolicy.addActions(
            "iam:UpdateAccessKey",
            "iam:ListAccessKeys",
            "iam:GetAccessKeyLastUsed",
            "iam:GetUser",
            "iam:GetLoginProfile",
            "iam:DeleteLoginProfile"
        );
        remediationPolicy.effect = Effect.ALLOW;
        remediationPolicy.addResources(
            "arn:" + this.partition + ":iam::" + this.account + ":user/*"
        );
        inlinePolicy.addStatements(remediationPolicy)

        const cfgPerms = new PolicyStatement();
        cfgPerms.addActions(
            "config:ListDiscoveredResources"
        )
        cfgPerms.effect = Effect.ALLOW
        cfgPerms.addResources("*")
        inlinePolicy.addStatements(cfgPerms)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for any resource.'
                }]
            }
        }
    }
    //-----------------------
    // AWSConfigRemediation-SetIAMPasswordPolicy
    //
    {
        const remediationName = 'SetIAMPasswordPolicy'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        
        const remediationPolicy = new PolicyStatement();
        remediationPolicy.addActions(
            "iam:UpdateAccountPasswordPolicy",
            "iam:GetAccountPasswordPolicy",
            "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress"
            )
        remediationPolicy.effect = Effect.ALLOW
        remediationPolicy.addResources("*")
        inlinePolicy.addStatements(remediationPolicy)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for any resource.'
                }]
            }
        }
    }

    //****
    //Create remediation books for CIS findings 3.1 through 3.14
    //

    {
        const remediationName = 'CreateLogMetricFilterAndAlarm'
        const inlinePolicy = new Policy(this, `SHARR-Remediation-Policy-${remediationName}`);
        
        const remediationPolicy = new PolicyStatement();
        remediationPolicy.addActions(
            "logs:PutMetricFilter",
            "cloudwatch:PutMetricAlarm"
            )
        remediationPolicy.effect = Effect.ALLOW
        remediationPolicy.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);
        remediationPolicy.addResources(`arn:${this.partition}:cloudwatch:*:${this.account}:alarm:*`);

        inlinePolicy.addStatements(remediationPolicy)

        new SsmRole(this, 'RemediationRole ' + remediationName, {
            solutionId: props.solutionId,
            ssmDocName: remediationName,
            adminAccountNumber: adminAccount.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            remediationRoleName: `${remediationRoleNameBase}${remediationName}_${this.region}`
        })

        new SsmRemediationRunbook(this, 'SHARR '+ remediationName, {
            ssmDocName: remediationName,
            ssmDocPath: ssmdocs,
            ssmDocFileName: `${remediationName}.yaml`,
            scriptPath: `${ssmdocs}/scripts`,
            solutionVersion: props.solutionVersion,
            solutionDistBucket: props.solutionDistBucket
        })
    }

  }
}
