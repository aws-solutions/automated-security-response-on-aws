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
// Member Stack - launched by the account admin in the member account.
// Creates local account roles to allow actions (read-only) by the Primary account
// Installs Playbook SSM Automation Documents
//
import * as cdk from '@aws-cdk/core';
import { 
    PolicyStatement, 
    PolicyDocument,
    Effect, 
    Role, 
    Policy, 
    ServicePrincipal, 
    CfnPolicy
} from '@aws-cdk/aws-iam';
import { Key } from '@aws-cdk/aws-kms';
import { StringParameter } from '@aws-cdk/aws-ssm';
import { SsmPlaybook, SsmRemediationRole } from '../../../lib/playbook-construct';
import { OrchestratorConstruct } from './afsbp-orchestrator-construct';
import { MemberStack } from '../../../lib/orchestrator_member-construct';
import { Rds6EnhancedMonitoringRole } from './rds6-remediation-resources';

export interface MyStackProps {
    description: string;
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionDistName: string;
    solutionName: string;
    securityStandard: string;
}

export class AfsbpMemberStack extends MemberStack {

  constructor(scope: cdk.App, id: string, props: MyStackProps) {
    super(scope, id, props);
    const adminRoleName = `${props.solutionId}-SHARR-Orchestrator-Admin_${this.region}`
    const memberRemediationRoleNameRoot = props.solutionId + '-SHARR-Remediation-AFSBP-'

    //--------------------------
    // KMS Customer Managed Key

    // Key Policy
    const kmsKeyPolicy:PolicyDocument = new PolicyDocument()
    const kmsPerms:PolicyStatement = new PolicyStatement();
    kmsPerms.addActions('kms:GenerateDataKey')
    kmsPerms.addActions('kms:Decrypt')
    kmsPerms.effect = Effect.ALLOW
    kmsPerms.addResources("*") // Only the key the policydocument is attached to
    kmsPerms.addPrincipals(new ServicePrincipal('sns.amazonaws.com'))
    kmsPerms.addPrincipals(new ServicePrincipal('s3.amazonaws.com'))
    kmsPerms.addPrincipals(new ServicePrincipal(`cloudtrail.${this.urlSuffix}`))
    kmsKeyPolicy.addStatements(kmsPerms)

    const kmsKey:Key = new Key(this, 'SHARR Key', {
        enableKeyRotation: true,
        alias: `${props.solutionId}-SHARR-AFSBP-Key`,
        trustAccountIdentities: true,
        policy: kmsKeyPolicy
    });

    new StringParameter(this, 'SHARR Key Alias', {
        description: 'KMS Customer Managed Key that will encrypt data for AFSBP remedations',
        parameterName: `/Solutions/${props.solutionId}/CMK_AFSBP_ARN`,
        stringValue: kmsKey.keyArn
    });

    //-----------------------
    // AutoScaling.1
    //
    {
        const controlId = 'AutoScaling.1'
        const inlinePolicy = new Policy(this, `SHARR-AFSBP-Member-Policy-${controlId}`);
        const asPerms = new PolicyStatement();
        asPerms.addActions("autoscaling:UpdateAutoScalingGroup")
        asPerms.addActions("autoscaling:DescribeAutoScalingGroups")
        asPerms.effect = Effect.ALLOW
        asPerms.addResources("*");
        inlinePolicy.addStatements(asPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            // adminAccountNumber: this.adminAccountNumber.valueAsString,
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: `${memberRemediationRoleNameRoot}${controlId}_${this.region}`
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP '+ controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_AutoScaling.1.yaml'
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

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
    // CloudTrail.1
    //
    {
        const controlId = 'CloudTrail.1'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        const cloudtrailPerms = new PolicyStatement();
        cloudtrailPerms.addActions("cloudtrail:CreateTrail")
        cloudtrailPerms.addActions("cloudtrail:UpdateTrail")
        cloudtrailPerms.addActions("cloudtrail:StartLogging")
        cloudtrailPerms.effect = Effect.ALLOW
        cloudtrailPerms.addResources("*");
        inlinePolicy.addStatements(cloudtrailPerms)

        const s3Perms = new PolicyStatement();
        s3Perms.addActions("s3:CreateBucket")
        s3Perms.addActions("s3:PutEncryptionConfiguration")
        s3Perms.addActions("s3:PutBucketPublicAccessBlock")
        s3Perms.addActions("s3:PutBucketLogging")
        s3Perms.addActions("s3:PutBucketAcl")
        s3Perms.addActions("s3:PutBucketPolicy")
        s3Perms.effect = Effect.ALLOW
        s3Perms.addResources(
            `arn:${this.partition}:s3:::so0111-*`
        );
        inlinePolicy.addStatements(s3Perms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: memberRemediationRoleNameRoot + controlId + '_' + this.region
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP '+ controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_CloudTrail.1.yaml'
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
    // CloudTrail.2
    //
    {
        const controlId = 'CloudTrail.2'
        const inlinePolicy = new Policy(this,`SHARR-AFSBP-Member-Policy-${controlId}`);
        const cloudtrailPerms = new PolicyStatement();
        cloudtrailPerms.addActions("cloudtrail:UpdateTrail")
        cloudtrailPerms.effect = Effect.ALLOW
        cloudtrailPerms.addResources("*");
        inlinePolicy.addStatements(cloudtrailPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: `${memberRemediationRoleNameRoot}${controlId}_${this.region}`
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP '+ controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_CloudTrail.2.yaml'
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
    // Config.1
    //
    {
        const controlId = 'Config.1'

        const inlinePolicy = new Policy(this, `SHARR-AFSBP-Member-Policy-${controlId}`);

        const iamPerms = new PolicyStatement();
        iamPerms.addActions("iam:GetRole")
        iamPerms.addActions("iam:PassRole")
        iamPerms.effect = Effect.ALLOW
        iamPerms.addResources(
            `arn:${this.partition}:iam::${this.account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig`
        );
        inlinePolicy.addStatements(iamPerms)

        const snsPerms = new PolicyStatement();
        snsPerms.addActions("sns:CreateTopic")
        snsPerms.addActions("sns:SetTopicAttributes")
        snsPerms.effect = Effect.ALLOW
        snsPerms.addResources(
            `arn:${this.partition}:sns:${this.region}:${this.account}:SO0111-SHARR-AFSBP-Config-1-AWSConfigNotification`
        );
        inlinePolicy.addStatements(snsPerms)

        const s3Perms = new PolicyStatement();
        s3Perms.addActions("s3:CreateBucket")
        s3Perms.addActions("s3:PutEncryptionConfiguration")
        s3Perms.addActions("s3:PutBucketPublicAccessBlock")
        s3Perms.addActions("s3:PutBucketLogging")
        s3Perms.addActions("s3:PutBucketAcl")
        s3Perms.addActions("s3:PutBucketPolicy")
        s3Perms.effect = Effect.ALLOW
        s3Perms.addResources(
            `arn:${this.partition}:s3:::so0111-*`
        );
        inlinePolicy.addStatements(s3Perms)

        const cfgPerms = new PolicyStatement();
        cfgPerms.addActions("config:PutConfigurationRecorder")
        cfgPerms.addActions("config:PutDeliveryChannel")
        cfgPerms.addActions("config:DescribeConfigurationRecorders")
        cfgPerms.addActions("config:StartConfigurationRecorder")
        cfgPerms.effect = Effect.ALLOW
        cfgPerms.addResources("*")
        inlinePolicy.addStatements(cfgPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, `RemediationRole ${controlId}`, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: `${memberRemediationRoleNameRoot}${controlId}_${this.region}`
        })
        // SSM Automation Document
        new SsmPlaybook(this, `AFSBP ${controlId}`, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_Config.1.yaml'
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
    // EC2.1
    //
    {
        const controlId = 'EC2.1'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        const ec2Perms = new PolicyStatement();
        ec2Perms.addActions("ec2:ModifySnapshotAttribute")
        ec2Perms.addActions("ec2:DescribeSnapshots")
        ec2Perms.effect = Effect.ALLOW
        ec2Perms.addResources("*");
        inlinePolicy.addStatements(ec2Perms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: memberRemediationRoleNameRoot + controlId + '_' + this.region
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP '+ controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_EC2.1.yaml'
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* RDS snapshot.'
                }]
            }
        }
    }

    //-----------------------
    // EC2.2
    //
    {
        const controlId = 'EC2.2'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        const ec2Perms = new PolicyStatement();
        ec2Perms.addActions("ec2:DescribeSecurityGroups")
        ec2Perms.addActions("ec2:RevokeSecurityGroupIngress")
        ec2Perms.addActions("ec2:RevokeSecurityGroupEgress")
        ec2Perms.effect = Effect.ALLOW
        ec2Perms.addResources("*");
        inlinePolicy.addStatements(ec2Perms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: memberRemediationRoleNameRoot + controlId + '_' + this.region
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP '+ controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_EC2.2.yaml'
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* Security Group.'
                }]
            }
        }
    }

    //-----------------------
    // EC2.7
    //
    {
        const controlId = 'EC2.7'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        const ec2Perms = new PolicyStatement();
        ec2Perms.addActions("ec2:EnableEBSEncryptionByDefault")
        ec2Perms.addActions("ec2:GetEbsEncryptionByDefault")
        ec2Perms.effect = Effect.ALLOW
        ec2Perms.addResources("*");
        inlinePolicy.addStatements(ec2Perms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: `${memberRemediationRoleNameRoot}${controlId}_${this.region}`
        })
        // SSM Automation Document
        new SsmPlaybook(this, `AFSBP ${controlId}`, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_EC2.7.yaml'
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* Security Group.'
                }]
            }
        }
    }

    //-----------------------
    // Lambda.1
    //
    {
        const controlId = 'Lambda.1'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        
        const lambdaPerms = new PolicyStatement();
        lambdaPerms.addActions("lambda:GetPolicy")
        lambdaPerms.addActions("lambda:RemovePermission")
        lambdaPerms.effect = Effect.ALLOW
        lambdaPerms.addResources('*')
        inlinePolicy.addStatements(lambdaPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: memberRemediationRoleNameRoot + controlId + '_' + this.region
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP ' + controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_Lambda.1.yaml'
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

    //-----------------------
    // RDS.1
    //
    {
        const controlId = 'RDS.1'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        const rdsPerms = new PolicyStatement();
        rdsPerms.addActions("rds:ModifyDBSnapshotAttribute")
        rdsPerms.addActions("rds:ModifyDBClusterSnapshotAttribute")
        rdsPerms.effect = Effect.ALLOW
        rdsPerms.addResources("*");
        inlinePolicy.addStatements(rdsPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole RDS.1', {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: memberRemediationRoleNameRoot + 'RDS.1' + '_' + this.region
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP RDS.1', {
            securityStandard: props.securityStandard,
            controlId: 'RDS.1',
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_RDS.1.yaml'
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* RDS snapshot.'
                }]
            }
        }
    }
    //-----------------------
    // RDS.6
    //
    {
        const controlId = 'RDS.6'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        
        const iamPerms = new PolicyStatement();
        iamPerms.addActions("iam:GetRole")
        iamPerms.addActions("iam:PassRole")
        iamPerms.effect = Effect.ALLOW
        iamPerms.addResources(
            'arn:' + this.partition + ':iam::' + this.account + ':role/SO0111-SHARR-RDSEnhancedMonitoring_*'
        );
        inlinePolicy.addStatements(iamPerms)

        const ssmPerms = new PolicyStatement();
        ssmPerms.addActions("ssm:StartAutomationExecution")
        ssmPerms.effect = Effect.ALLOW
        ssmPerms.addResources(
            'arn:' + this.partition + ':ssm:*:*:document/AWSConfigRemediation-EnableEnhancedMonitoringOnRDSInstance'
        );
        ssmPerms.addResources(
            'arn:' + this.partition + ':ssm:*:*:automation-definition/*'
        );
        inlinePolicy.addStatements(ssmPerms)

        const rdsPerms = new PolicyStatement();
        rdsPerms.addActions("rds:DescribeDBInstances")
        rdsPerms.addActions("rds:ModifyDBInstance")
        rdsPerms.effect = Effect.ALLOW
        rdsPerms.addResources("*");
        inlinePolicy.addStatements(rdsPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole RDS.6', {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: `${memberRemediationRoleNameRoot}${controlId}_${this.region}`
        })
        // SSM Automation Document
        new SsmPlaybook(this, `AFSBP ${controlId}`, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_RDS.6.yaml'
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
        // roleName MUST match that in AFSBP_RDS.6.yaml in the GetMonitoringRoleArn script, 
        new Rds6EnhancedMonitoringRole(this, 'Rds6EnhancedMonitoringRole',  {
            roleName: `${props.solutionId}-SHARR-RDSEnhancedMonitoring_${this.region}`
        })
    }

    //-----------------------
    // RDS.7
    //
    {
        const controlId = 'RDS.7'
        const inlinePolicy = new Policy(this, 'SHARR-AFSBP-Member-Policy-' + controlId);
        
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
        rdsPerms.addActions("rds:DescribeDBClusters")
        rdsPerms.addActions("rds:ModifyDBCluster")
        rdsPerms.effect = Effect.ALLOW
        rdsPerms.addResources("*");
        inlinePolicy.addStatements(rdsPerms)

        // Create the role. Policies to be added below as inline. One role per 
        // remediation 
        new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
            solutionId: props.solutionId,
            controlId: controlId,
            adminAccountNumber: this.adminAccountNumber.valueAsString,
            remediationPolicy: inlinePolicy,
            adminRoleName: adminRoleName,
            remediationRoleName: memberRemediationRoleNameRoot + controlId + '_' + this.region
        })
        // SSM Automation Document
        new SsmPlaybook(this, 'AFSBP ' + controlId, {
            securityStandard: props.securityStandard,
            controlId: controlId,
            ssmDocPath: './ssmdocs/',
            ssmDocFileName: 'AFSBP_RDS.7.yaml'
        })
        // CFN-NAG
        // WARN W12: IAM policy should not allow * resource

        let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
            cfn_nag: {
                rules_to_suppress: [{
                    id: 'W12',
                    reason: 'Resource * is required for to allow remediation for *any* RDS instance.'
                }]
            }
        }
    }

      //-----------------------
      // S3.8
      //
      {
          const controlId = 'S3.8'
          const inlinePolicy = new Policy(this, `SHARR-AFSBP-Member-Policy-${controlId}`);

          const s3Permission = new PolicyStatement();
          s3Permission.addActions("s3:PutBucketPublicAccessBlock")
          s3Permission.effect = Effect.ALLOW
          s3Permission.addResources('*')
          inlinePolicy.addStatements(s3Permission)

          // Create the role. Policies to be added below as inline. One role per
          // remediation
          new SsmRemediationRole(this, 'RemediationRole ' + controlId, {
              solutionId: props.solutionId,
              controlId: controlId,
              adminAccountNumber: this.adminAccountNumber.valueAsString,
              remediationPolicy: inlinePolicy,
              adminRoleName: adminRoleName,
              remediationRoleName: memberRemediationRoleNameRoot + controlId + '_' + this.region
          })
          // SSM Automation Document
          new SsmPlaybook(this, 'AFSBP ' + controlId, {
              securityStandard: props.securityStandard,
              controlId: controlId,
              ssmDocPath: './ssmdocs/',
              ssmDocFileName: 'AFSBP_S3.8.yaml'
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
  }
}
