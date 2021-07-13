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
import { PolicyStatement, Effect, PolicyDocument, Role, ServicePrincipal, CfnRole } from '@aws-cdk/aws-iam';
import { AssumeRoleConstruct } from '../../../lib/assume-role-construct';

export interface CisStackProps {
    description: string;
    solutionId: string;
    solutionVersion: string;
    solutionDistBucket: string;
    solutionDistName: string;
    solutionName: string;
}
export class CisPermissionsStack extends cdk.Stack {

  constructor(scope: cdk.App, id: string, props: CisStackProps) {
    super(scope, id, props);

    const adminAccountNumber = new cdk.CfnParameter(this, 'AdminAccountNumber', {
        description: "Administrator account number ",
        type: "Number"
    });

    //DEFINE PRINCIPLE RESOURCE WHICH WILL ASSUME THE ROLE.
    //Used by all lambda roles
    let principalPolicyStatement = new PolicyStatement();
    principalPolicyStatement.addActions("sts:AssumeRole");
    principalPolicyStatement.effect = Effect.ALLOW;
    

    //CIS 1.3 - 1.4
    const cis1314 = new PolicyStatement();
    cis1314.addActions("iam:UpdateAccessKey");
    cis1314.addActions("iam:ListAccessKeys");
    cis1314.effect = Effect.ALLOW;
    cis1314.addResources(
        "arn:" + this.partition + ":iam::" + this.account + ":user/*"
    );

    const cis1314Policy = new PolicyDocument();
    cis1314Policy.addStatements(cis1314)

    new AssumeRoleConstruct(this, 'cis1314assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis1314Policy,
        lambdaHandlerName: 'CIS1314',
        region: this.region,
        aws_partition: this.partition
    });

    // //CIS 1.5 - 1.11
    const cis15111 = new PolicyStatement();
    cis15111.addActions("iam:UpdateAccountPasswordPolicy")
    cis15111.effect = Effect.ALLOW
    cis15111.addResources("*");

    const cis15111Policy = new PolicyDocument();
    cis15111Policy.addStatements(cis15111)

    new AssumeRoleConstruct(this, 'cis1511assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis15111Policy,
        lambdaHandlerName: 'CIS15111',
        region: this.region,
        aws_partition: this.partition
    });

    // //CIS 1.16
    const cis116_iam_1 = new PolicyStatement();
    cis116_iam_1.addActions("iam:GetGroup")
    cis116_iam_1.addActions("iam:CreateGroup")
    cis116_iam_1.addActions("iam:AddUserToGroup")
    cis116_iam_1.addActions("iam:AttachGroupPolicy")
    cis116_iam_1.effect = Effect.ALLOW
    cis116_iam_1.addResources(`arn:${this.partition}:iam::${this.account}:group/*`);

    const cis116_iam_2 = new PolicyStatement();
    cis116_iam_2.addActions("iam:CreatePolicy")
    cis116_iam_2.effect = Effect.ALLOW
    cis116_iam_2.addResources(`arn:${this.partition}:iam::${this.account}:policy/*`);

    const cis116_iam_3 = new PolicyStatement();
    cis116_iam_3.addActions("iam:GetUserPolicy")
    cis116_iam_3.addActions("iam:DeleteUserPolicy")
    cis116_iam_3.addActions("iam:DetachUserPolicy")
    cis116_iam_3.effect = Effect.ALLOW
    cis116_iam_3.addResources(`arn:${this.partition}:iam::${this.account}:user/*`);


    const cis116Policy = new PolicyDocument();
    cis116Policy.addStatements(cis116_iam_1)
    cis116Policy.addStatements(cis116_iam_2)
    cis116Policy.addStatements(cis116_iam_3)

    new AssumeRoleConstruct(this, 'cis116assumerole', {
      adminAccountNumber: adminAccountNumber,
      solutionId: props.solutionId,
      lambdaPolicy: cis116Policy,
      lambdaHandlerName: 'CIS116',
      region: this.region,
      aws_partition: this.partition
    });

    // //CIS 1.20
    const cis120_iam = new PolicyStatement();
    cis120_iam.addActions("iam:GetRole")
    cis120_iam.addActions("iam:CreateRole")
    cis120_iam.addActions("iam:AttachRolePolicy")
    cis120_iam.addActions("iam:TagRole")
    cis120_iam.effect = Effect.ALLOW
    cis120_iam.addResources(`arn:${this.partition}:iam::${this.account}:role/*`);

    const cis120Policy = new PolicyDocument();
    cis120Policy.addStatements(cis120_iam)

    new AssumeRoleConstruct(this, 'cis120assumerole', {
      adminAccountNumber: adminAccountNumber,
      solutionId: props.solutionId,
      lambdaPolicy: cis120Policy,
      lambdaHandlerName: 'CIS120',
      region: this.region,
      aws_partition: this.partition
    });

    // //CIS 2.2
    const cis22 = new PolicyStatement();
    cis22.addActions("cloudtrail:UpdateTrail")
    cis22.effect = Effect.ALLOW
    cis22.addResources(
        "arn:" + this.partition + ":cloudtrail:*:" + this.account + ":trail/*"
    );

    const cis22Policy = new PolicyDocument();
    cis22Policy.addStatements(cis22)

    new AssumeRoleConstruct(this, 'cis22assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis22Policy,
        lambdaHandlerName: 'CIS22',
        region: this.region,
        aws_partition: this.partition
    });

    // //CIS 2.3
    const cis23s3 = new PolicyStatement();
    cis23s3.addActions("s3:PutBucketPublicAccessBlock");
    cis23s3.effect = Effect.ALLOW
    cis23s3.addResources("*")

    const cis23Policy = new PolicyDocument();
    cis23Policy.addStatements(cis23s3)

    new AssumeRoleConstruct(this, 'cis23assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis23Policy,
        lambdaHandlerName: 'CIS23',
        region: this.region,
        aws_partition: this.partition
    });

    //CIS 2.4
    const cis24ct = new PolicyStatement();
    cis24ct.addActions("cloudtrail:UpdateTrail")

    cis24ct.effect = Effect.ALLOW
    cis24ct.addResources(
        "arn:" + this.partition + ":cloudtrail:*:" + this.account + ":trail/*"
    );

    const cis24iam = new PolicyStatement();
    cis24iam.addActions("iam:PassRole")
    cis24iam.addResources(
        "arn:" + this.partition + ":iam::" + this.account + ":role/" + props.solutionId + 
        "_CIS24_remediationRole_" + this.region
    );

    const cis24logs = new PolicyStatement();
    cis24logs.addActions("logs:CreateLogGroup")
    cis24logs.addActions("logs:DescribeLogGroups")
    cis24logs.effect = Effect.ALLOW
    cis24logs.addResources("*");

    const cis24Policy = new PolicyDocument();
    cis24Policy.addStatements(cis24iam)
    cis24Policy.addStatements(cis24ct)
    cis24Policy.addStatements(cis24logs)

    new AssumeRoleConstruct(this, 'cis24assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis24Policy,
        lambdaHandlerName: 'CIS24',
        region: this.region,
        aws_partition: this.partition
    });

    const cis24_remediation_policy_statement_1 = new PolicyStatement()
    cis24_remediation_policy_statement_1.addActions("logs:CreateLogStream")
    cis24_remediation_policy_statement_1.effect = Effect.ALLOW
    cis24_remediation_policy_statement_1.addResources(
        "arn:" + this.partition + ":logs:*:*:log-group:*"
    )

    const cis24_remediation_policy_statement_2 = new PolicyStatement()
    cis24_remediation_policy_statement_2.addActions("logs:PutLogEvents")
    cis24_remediation_policy_statement_2.effect = Effect.ALLOW
    cis24_remediation_policy_statement_2.addResources(
        "arn:" + this.partition + ":logs:*:*:log-group:*:log-stream:*"
    )

    const cis24_remediation_policy_doc = new PolicyDocument()
    cis24_remediation_policy_doc.addStatements(cis24_remediation_policy_statement_1) 
    cis24_remediation_policy_doc.addStatements(cis24_remediation_policy_statement_2) 

    const cis24_remediation_role = new Role(this, 'cis24remediationrole', {
        assumedBy: new ServicePrincipal(`cloudtrail.${this.urlSuffix}`),
        inlinePolicies: {
            'default_lambdaPolicy': cis24_remediation_policy_doc
        },
        roleName: props.solutionId + '_CIS24_remediationRole_' + this.region
    });

    const cis24RoleResource = cis24_remediation_role.node.findChild('Resource') as CfnRole;

    cis24RoleResource.cfnOptions.metadata = {
        cfn_nag: {
            rules_to_suppress: [{
                id: 'W28',
                reason: 'Static names chosen intentionally to provide integration in cross-account permissions'
            }]
        }
    };

    //CIS 2.6
    const cis26ssm = new PolicyStatement();
    cis26ssm.addActions("ssm:StartAutomationExecution")
    cis26ssm.effect = Effect.ALLOW
    cis26ssm.addResources(
        'arn:' + this.partition + ':ssm:' + this.region + ':' +
        this.account + ':document/AWS-ConfigureS3BucketLogging'
    );
    cis26ssm.addResources(
        'arn:' + this.partition + ':ssm:' + this.region + ':*:automation-definition/*'
    );

    const cis26s3 = new PolicyStatement();
    cis26s3.addActions("s3:PutBucketLogging")
    cis26s3.addActions("s3:CreateBucket")
    cis26s3.addActions("s3:PutEncryptionConfiguration")
    cis26s3.addActions("s3:PutBucketAcl")
    cis26s3.effect = Effect.ALLOW
    cis26s3.addResources("*");
    
    const cis26iam = new PolicyStatement();
    cis26iam.addActions("iam:PassRole")
    cis26iam.effect = Effect.ALLOW
    cis26iam.addResources(
        'arn:' + this.partition + ':iam::' + this.account +
        ':role/' + props.solutionId + '_CIS26_memberRole_' + this.region
    );

    const cis26Policy = new PolicyDocument();
    cis26Policy.addStatements(cis26ssm)
    cis26Policy.addStatements(cis26s3)
    cis26Policy.addStatements(cis26iam)

    new AssumeRoleConstruct(this, 'cis26assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis26Policy,
        lambdaHandlerName: 'CIS26',
        service: 'ssm.amazonaws.com',
        region: this.region,
        aws_partition: this.partition
    });

    //CIS 2.8
    const cis28kms = new PolicyStatement();
    cis28kms.addActions("kms:EnableKeyRotation")
    cis28kms.addActions("kms:GetKeyRotationStatus")
    cis28kms.effect = Effect.ALLOW
    cis28kms.addResources(
        "arn:" + this.partition + ":kms:*:"+this.account+":key/*"
    );

    const cis28Policy = new PolicyDocument();
    cis28Policy.addStatements(cis28kms)

    new AssumeRoleConstruct(this, 'cis28assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis28Policy,
        lambdaHandlerName: 'CIS28',
        region: this.region,
        aws_partition: this.partition
    });

    //CIS 2.9
    const cis29_1 = new PolicyStatement();
    cis29_1.addActions("ec2:CreateFlowLogs")
    cis29_1.effect = Effect.ALLOW
    cis29_1.addResources("arn:" + this.partition + ":ec2:*:*:vpc/*");
    cis29_1.addResources("arn:" + this.partition + ":ec2:*:*:vpc-flow-log/*");


    const cis29iam = new PolicyStatement();
    cis29iam.addActions("iam:PassRole")
    cis29iam.addResources(
        "arn:" + this.partition + ":iam::" + this.account + ":role/" + props.solutionId + 
        "_CIS29_remediationRole_" + this.region
    );

    const cis29_2 = new PolicyStatement()
    cis29_2.addActions("ec2:DescribeFlowLogs")
    cis29_2.addActions("logs:CreateLogGroup")
    cis29_2.effect = Effect.ALLOW
    cis29_2.addResources("*");

    const cis29Policy = new PolicyDocument();
    cis29Policy.addStatements(cis29_1)
    cis29Policy.addStatements(cis29_2)
    cis29Policy.addStatements(cis29iam)

    new AssumeRoleConstruct(this, 'cis29assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis29Policy,
        lambdaHandlerName: 'CIS29',
        region: this.region,
        aws_partition: this.partition
    });

    //CIS 2.9 Remediation Role
    const cis29_remediation_stat = new PolicyStatement()
    cis29_remediation_stat.effect = Effect.ALLOW
    cis29_remediation_stat.addActions("logs:CreateLogGroup")
    cis29_remediation_stat.addActions("logs:CreateLogStream")
    cis29_remediation_stat.addActions("logs:DescribeLogGroups")
    cis29_remediation_stat.addActions("logs:DescribeLogStreams")
    cis29_remediation_stat.addActions("logs:PutLogEvents")
    cis29_remediation_stat.addResources("*")

    const cis29_remediation_doc = new PolicyDocument()
    cis29_remediation_doc.addStatements(cis29_remediation_stat)

    const cis29_remediation_role = new Role(this, 'cis29remediationrole', {
        assumedBy: new ServicePrincipal('vpc-flow-logs.amazonaws.com'),
        inlinePolicies: {
            'default_lambdaPolicy': cis29_remediation_doc
        },
        roleName: props.solutionId + '_CIS29_remediationRole_' + this.region
    });

    const cis29RoleResource = cis29_remediation_role.node.findChild('Resource') as CfnRole;

    cis29RoleResource.cfnOptions.metadata = {
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

    //CIS 4.1 & 4.2
    const cis4142ec2 = new PolicyStatement();
    cis4142ec2.addActions("ec2:DescribeSecurityGroupReferences")
    cis4142ec2.addActions("ec2:DescribeSecurityGroups")
    cis4142ec2.addActions("ec2:UpdateSecurityGroupRuleDescriptionsEgress")
    cis4142ec2.addActions("ec2:UpdateSecurityGroupRuleDescriptionsIngress")
    cis4142ec2.addActions("ec2:RevokeSecurityGroupIngress")
    cis4142ec2.addActions("ec2:RevokeSecurityGroupEgress")
    cis4142ec2.effect = Effect.ALLOW
    cis4142ec2.addResources("*");

    const cis4142iam = new PolicyStatement();
    cis4142iam.addActions("iam:PassRole")
    cis4142iam.effect = Effect.ALLOW
    cis4142iam.addResources(
        'arn:' + this.partition + ':iam::' + this.account +
        ':role/' + props.solutionId + '_CIS4142_memberRole_' + this.region
    );

    const cis4142ssm = new PolicyStatement();
    cis4142ssm.addActions("ssm:StartAutomationExecution")
    cis4142ssm.effect = Effect.ALLOW
    cis4142ssm.addResources(
        'arn:' + this.partition + ':ssm:' + this.region + ':' +
        this.account + ':document/AWS-DisablePublicAccessForSecurityGroup'
    );
    cis4142ssm.addResources(
        'arn:' + this.partition + ':ssm:' + this.region + ':*:automation-definition/*'
    );

    const cis4142Policy = new PolicyDocument();
    cis4142Policy.addStatements(cis4142ec2)
    cis4142Policy.addStatements(cis4142ssm)
    cis4142Policy.addStatements(cis4142iam)

    new AssumeRoleConstruct(this, 'cis4142assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis4142Policy,
        lambdaHandlerName: 'CIS4142',
        service: 'ssm.amazonaws.com',
        region: this.region,
        aws_partition: this.partition
    });

    //CIS 4.3
    const cis43_1 = new PolicyStatement();
    cis43_1.addActions("ec2:UpdateSecurityGroupRuleDescriptionsEgress")
    cis43_1.addActions("ec2:UpdateSecurityGroupRuleDescriptionsIngress")
    cis43_1.addActions("ec2:RevokeSecurityGroupIngress")
    cis43_1.addActions("ec2:RevokeSecurityGroupEgress")
    cis43_1.effect = Effect.ALLOW
    cis43_1.addResources("arn:" + this.partition + ":ec2:*:"+this.account+":security-group/*");

    const cis43_2 = new PolicyStatement()
    cis43_2.addActions("ec2:DescribeSecurityGroupReferences")
    cis43_2.addActions("ec2:DescribeSecurityGroups")
    cis43_2.effect = Effect.ALLOW
    cis43_2.addResources("*")

    const cis43Policy = new PolicyDocument();
    cis43Policy.addStatements(cis43_1)
    cis43Policy.addStatements(cis43_2)

    new AssumeRoleConstruct(this, 'cis43assumerole', {
        adminAccountNumber: adminAccountNumber,
        solutionId: props.solutionId,
        lambdaPolicy: cis43Policy,
        lambdaHandlerName: 'CIS43',
        region: this.region,
        aws_partition: this.partition
    });
  }
}
