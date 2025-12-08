// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//
// Remediation Runbook Stack - installs non standard-specific remediation
// runbooks that are used by one or more standards
//
import * as cdk from 'aws-cdk-lib';
import { Aspects, CfnParameter } from 'aws-cdk-lib';
import {
  CfnPolicy,
  CfnRole,
  Effect,
  InstanceProfile,
  ManagedPolicy,
  Policy,
  PolicyDocument,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Rds6EnhancedMonitoringRole } from './rds6-remediation-resources';
import { RunbookFactory } from './runbook_factory';
import { SNS2DeliveryStatusLoggingRole } from './sns2-remediation-resources';
import { SsmRole } from './ssmplaybook';
import { WaitProvider } from './wait-provider';
import SsmDocRateLimit from './ssm-doc-rate-limit';
import NamespaceParam from './parameters/namespace-param';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { MemberRolesStack } from './member-roles-stack';

export interface StackProps extends cdk.StackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
  readonly parameters: Record<string, any>;
  ssmdocs?: string;
  roleStack: MemberRolesStack;
}

export class RemediationRunbookStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: StackProps) {
    super(scope, id, props);

    const waitProviderServiceTokenParam = new CfnParameter(this, 'WaitProviderServiceToken');

    const namespaceParam = new NamespaceParam(this, 'Namespace');

    const waitProvider = WaitProvider.fromServiceToken(
      this,
      'WaitProvider',
      waitProviderServiceTokenParam.valueAsString,
    );
    const namespace = namespaceParam.value;

    Aspects.of(this).add(new SsmDocRateLimit(waitProvider));

    let ssmdocs = '';
    if (props.ssmdocs == undefined) {
      ssmdocs = '../remediation_runbooks';
    } else {
      ssmdocs = props.ssmdocs;
    }

    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
    const remediationRoleNameBase = `${RESOURCE_PREFIX}-`;

    //-----------------------
    // Common IAM Policy statements
    //
    const iamGetRolePerms = new PolicyStatement();
    iamGetRolePerms.addActions('iam:GetRole');
    iamGetRolePerms.effect = Effect.ALLOW;
    iamGetRolePerms.addResources(`arn:${this.partition}:iam::${this.account}:role/*`);

    const iamCreateServiceLinkedRolePerms = new PolicyStatement();
    iamCreateServiceLinkedRolePerms.addActions('iam:CreateServiceLinkedRole');
    iamCreateServiceLinkedRolePerms.effect = Effect.ALLOW;
    iamCreateServiceLinkedRolePerms.addResources(`arn:${this.partition}:iam::${this.account}:role/aws-service-role/*`);

    const iamServiceLinkedRolePolicyPerms = new PolicyStatement();
    iamServiceLinkedRolePolicyPerms.addActions('iam:AttachRolePolicy', 'iam:PutRolePolicy');
    iamServiceLinkedRolePolicyPerms.effect = Effect.ALLOW;
    iamServiceLinkedRolePolicyPerms.addResources(
      `arn:${this.partition}:iam::${this.account}:role/aws-service-role/cloudtrail.amazonaws.com/*`,
    );

    // IAM actions that can be used for privilege escalation
    const PRIVILEGE_ESCALATION_ACTIONS = [
      'iam:AddUserToGroup',
      'iam:AttachGroupPolicy',
      'iam:AttachRolePolicy',
      'iam:AttachUserPolicy',
      'iam:CreatePolicyVersion',
      'iam:CreateRole',
      'iam:DeleteGroupPolicy',
      'iam:DeleteRolePolicy',
      'iam:DeleteUserPolicy',
      'iam:DetachGroupPolicy',
      'iam:DetachRolePolicy',
      'iam:DetachUserPolicy',
      'iam:PutGroupPolicy',
      'iam:PutRolePolicy',
      'iam:PutUserPolicy',
      'iam:RemoveUserFromGroup',
      'iam:SetDefaultPolicyVersion',
      'iam:UpdateAssumeRolePolicy',
      'iam:UpdateRole',
    ];

    const denyPrivilegeEscalation = new PolicyStatement();
    denyPrivilegeEscalation.addActions(...PRIVILEGE_ESCALATION_ACTIONS);
    denyPrivilegeEscalation.effect = Effect.DENY;
    denyPrivilegeEscalation.addResources(
      `arn:${this.partition}:iam::${this.account}:role/${RESOURCE_PREFIX}-*`,
      `arn:${this.partition}:iam::${this.account}:user/*`,
    );

    const orgListServiceAccessPerms = new PolicyStatement();
    orgListServiceAccessPerms.addActions('organizations:ListAWSServiceAccessForOrganization');
    orgListServiceAccessPerms.effect = Effect.ALLOW;
    orgListServiceAccessPerms.addResources('*');

    const redshiftModifyClusterDependentPerms = new PolicyStatement();
    redshiftModifyClusterDependentPerms.addActions(
      'kms:Decrypt',
      'kms:RetireGrant',
      'kms:GenerateDataKey',
      'kms:DescribeKey',
      'kms:CreateGrant',
      'secretsmanager:DescribeSecret',
      'secretsmanager:CreateSecret',
      'secretsmanager:DeleteSecret',
      'secretsmanager:UpdateSecret',
      'secretsmanager:RotateSecret',
      'secretsmanager:TagResource',
      'acm:DescribeCertificate',
    );
    redshiftModifyClusterDependentPerms.effect = Effect.ALLOW;
    redshiftModifyClusterDependentPerms.addResources(
      `arn:${this.partition}:secretsmanager:*:${this.account}:secret:*`,
      `arn:${this.partition}:kms:*:${this.account}:key/*`,
      `arn:${this.partition}:acm:*:${this.account}:certificate/*`,
    );

    const secretsManagerGetRandomPasswordPerms = new PolicyStatement();
    secretsManagerGetRandomPasswordPerms.addActions('secretsmanager:GetRandomPassword');
    secretsManagerGetRandomPasswordPerms.effect = Effect.ALLOW;
    secretsManagerGetRandomPasswordPerms.addResources('*');

    const rdsDependentPerms = new PolicyStatement();
    rdsDependentPerms.addActions(
      'rds:AddTagsToResource',
      'kms:Decrypt',
      'secretsmanager:CreateSecret',
      'kms:GenerateDataKey',
      'secretsmanager:RotateSecret',
      'kms:DescribeKey',
      'kms:CreateGrant',
      'rds:CreateTenantDatabase',
      'secretsmanager:TagResource',
    );
    rdsDependentPerms.effect = Effect.ALLOW;
    rdsDependentPerms.addResources(
      `arn:${this.partition}:kms:*:${this.account}:key/*`,
      `arn:${this.partition}:rds:*:${this.account}:pg:*`,
      `arn:${this.partition}:rds:*:${this.account}:og:*`,
      `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
      `arn:${this.partition}:rds:*:${this.account}:db:*`,
      `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
      `arn:${this.partition}:secretsmanager:*:${this.account}:secret:*`,
    );

    const rdsDependentIamRolePerms = new PolicyStatement();
    rdsDependentIamRolePerms.addActions('iam:GetRole', 'iam:PassRole');
    rdsDependentIamRolePerms.effect = Effect.ALLOW;
    rdsDependentIamRolePerms.addResources(
      'arn:' + this.partition + ':iam::' + this.account + ':role/RDSEnhancedMonitoringRole',
      `arn:${this.partition}:iam::${this.account}:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS`,
    );

    const ec2DescribeSecurityGroupRulesPerms = new PolicyStatement();
    ec2DescribeSecurityGroupRulesPerms.addActions('ec2:DescribeSecurityGroupRules');
    ec2DescribeSecurityGroupRulesPerms.effect = Effect.ALLOW;
    ec2DescribeSecurityGroupRulesPerms.addResources('*');

    const ec2SecurityGroupRevokeIngressPerms = new PolicyStatement();
    ec2SecurityGroupRevokeIngressPerms.addActions('ec2:RevokeSecurityGroupIngress');
    ec2SecurityGroupRevokeIngressPerms.effect = Effect.ALLOW;
    ec2SecurityGroupRevokeIngressPerms.addResources(`arn:${this.partition}:ec2:*:${this.account}:security-group/*`);

    //-----------------------
    // CreateCloudTrailMultiRegionTrail
    //
    {
      const remediationName = 'CreateCloudTrailMultiRegionTrail';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const cloudtrailPerms = new PolicyStatement();
      cloudtrailPerms.addActions(
        'cloudtrail:CreateTrail',
        'cloudtrail:UpdateTrail',
        'cloudtrail:StartLogging',
        'cloudtrail:AddTags',
      );
      cloudtrailPerms.effect = Effect.ALLOW;
      cloudtrailPerms.addResources(`arn:${this.partition}:cloudtrail:*:${this.account}:trail/*`);
      inlinePolicy.addStatements(cloudtrailPerms);

      const cloudtrailDescribePerms = new PolicyStatement();
      cloudtrailDescribePerms.addActions('cloudtrail:DescribeTrails');
      cloudtrailDescribePerms.effect = Effect.ALLOW;
      cloudtrailDescribePerms.addResources('*');
      inlinePolicy.addStatements(cloudtrailDescribePerms);

      const iamPassRolePerms = new PolicyStatement();
      iamPassRolePerms.addActions('iam:PassRole');
      iamPassRolePerms.effect = Effect.ALLOW;
      iamPassRolePerms.addResources(
        `arn:${this.partition}:iam::${this.account}:role/aws-service-role/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail`,
      );
      inlinePolicy.addStatements(iamPassRolePerms);
      inlinePolicy.addStatements(iamGetRolePerms);
      inlinePolicy.addStatements(iamCreateServiceLinkedRolePerms);
      inlinePolicy.addStatements(denyPrivilegeEscalation);
      inlinePolicy.addStatements(orgListServiceAccessPerms);

      const s3Perms = new PolicyStatement();
      s3Perms.addActions(
        's3:CreateBucket',
        's3:PutEncryptionConfiguration',
        's3:PutBucketPublicAccessBlock',
        's3:PutBucketLogging',
        's3:PutBucketAcl',
        's3:PutBucketPolicy',
        's3:PutBucketOwnershipControls',
      );
      s3Perms.effect = Effect.ALLOW;
      s3Perms.addResources(`arn:${this.partition}:s3:::so0111-*`);
      inlinePolicy.addStatements(s3Perms);

      const kmsPerms = new PolicyStatement();
      kmsPerms.addActions('kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey', 'kms:CreateGrant');
      kmsPerms.effect = Effect.ALLOW;
      kmsPerms.addResources(`arn:${this.partition}:kms:*:${this.account}:key/*`);
      inlinePolicy.addStatements(kmsPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason:
                'Resource * is required for cloudtrail:DescribeTrails to check existing trails and for KMS operations on customer-managed keys.',
            },
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide integration in cross-account permissions.',
            },
          ],
        },
      };
    }
    //-----------------------
    // CreateLogMetricAndAlarm
    //
    {
      const remediationName = 'CreateLogMetricFilterAndAlarm';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('logs:PutMetricFilter', 'cloudwatch:PutMetricAlarm');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);
      remediationPolicy.addResources(`arn:${this.partition}:cloudwatch:*:${this.account}:alarm:*`);
      inlinePolicy.addStatements(remediationPolicy);

      const logGroupCreatePerms = new PolicyStatement();
      logGroupCreatePerms.addActions('logs:CreateLogGroup');
      logGroupCreatePerms.effect = Effect.ALLOW;
      logGroupCreatePerms.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);
      inlinePolicy.addStatements(logGroupCreatePerms);

      const logGroupDescribePerms = new PolicyStatement();
      logGroupDescribePerms.addActions('logs:DescribeLogGroups');
      logGroupDescribePerms.effect = Effect.ALLOW;
      logGroupDescribePerms.addResources('*');
      inlinePolicy.addStatements(logGroupDescribePerms);

      {
        const snsPerms = new PolicyStatement();
        snsPerms.addActions('sns:CreateTopic', 'sns:SetTopicAttributes');
        snsPerms.effect = Effect.ALLOW;
        snsPerms.addResources(`arn:${this.partition}:sns:*:${this.account}:SO0111-ASR-LocalAlarmNotification`);
        inlinePolicy.addStatements(snsPerms);
      }

      const kmsPerms = new PolicyStatement();
      kmsPerms.addActions('kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey', 'kms:CreateGrant');
      kmsPerms.effect = Effect.ALLOW;
      kmsPerms.addResources(`arn:${this.partition}:kms:*:${this.account}:key/*`);
      inlinePolicy.addStatements(kmsPerms);

      const ssmPerms = new PolicyStatement();
      ssmPerms.addActions('ssm:PutParameter');
      ssmPerms.effect = Effect.ALLOW;
      ssmPerms.addResources(`arn:${this.partition}:ssm:*:${this.account}:parameter/Solutions/SO0111/*`);
      inlinePolicy.addStatements(ssmPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason:
                'Resource * is required for logs:DescribeLogGroups to list all log groups and for KMS operations on customer-managed keys.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableAutoScalingGroupELBHealthCheck
    //
    {
      const remediationName = 'EnableAutoScalingGroupELBHealthCheck';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const autoScalingWritePerms = new PolicyStatement();
      autoScalingWritePerms.addActions('autoscaling:UpdateAutoScalingGroup');
      autoScalingWritePerms.effect = Effect.ALLOW;
      autoScalingWritePerms.addResources(
        `arn:${this.partition}:autoscaling:*:${this.account}:autoScalingGroup:*:autoScalingGroupName/*`,
      );
      inlinePolicy.addStatements(autoScalingWritePerms);

      const autoScalingReadPerms = new PolicyStatement();
      autoScalingReadPerms.addActions('autoscaling:DescribeAutoScalingGroups');
      autoScalingReadPerms.effect = Effect.ALLOW;
      autoScalingReadPerms.addResources('*');
      inlinePolicy.addStatements(autoScalingReadPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* ASG.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableAWSConfig
    //
    {
      const remediationName = 'EnableAWSConfig';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      {
        const iamPerms = new PolicyStatement();
        iamPerms.addActions('iam:GetRole', 'iam:PassRole');
        iamPerms.effect = Effect.ALLOW;
        iamPerms.addResources(
          `arn:${this.partition}:iam::${this.account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig`,
          `arn:${this.partition}:iam::${
            this.account
          }:role/SO0111-CreateAccessLoggingBucket-${props.roleStack.getNamespace()}`,
        );
        inlinePolicy.addStatements(iamPerms);
      }
      {
        const snsPerms = new PolicyStatement();
        snsPerms.addActions('sns:CreateTopic', 'sns:SetTopicAttributes');
        snsPerms.effect = Effect.ALLOW;
        snsPerms.addResources(`arn:${this.partition}:sns:*:${this.account}:SO0111-ASR-AWSConfigNotification`);
        inlinePolicy.addStatements(snsPerms);
      }
      {
        const ssmPerms = new PolicyStatement();
        ssmPerms.addActions('ssm:StartAutomationExecution');
        ssmPerms.effect = Effect.ALLOW;
        ssmPerms.addResources(
          `arn:${this.partition}:ssm:*:${this.account}:automation-definition/ASR-CreateAccessLoggingBucket:*`,
        );
        inlinePolicy.addStatements(ssmPerms);
      }
      {
        const configPerms = new PolicyStatement();
        configPerms.addActions(
          'ssm:GetAutomationExecution',
          'config:PutConfigurationRecorder',
          'config:PutDeliveryChannel',
          'config:DescribeConfigurationRecorders',
          'config:StartConfigurationRecorder',
          'config:DescribeDeliveryChannels',
          'config:DescribeConfigurationRecorderStatus',
        );
        configPerms.effect = Effect.ALLOW;
        configPerms.addResources(`*`);
        inlinePolicy.addStatements(configPerms);
      }

      const s3Perms = new PolicyStatement();
      s3Perms.addActions(
        's3:CreateBucket',
        's3:PutEncryptionConfiguration',
        's3:PutBucketPublicAccessBlock',
        's3:PutBucketLogging',
        's3:PutBucketAcl',
        's3:PutBucketPolicy',
      );
      s3Perms.effect = Effect.ALLOW;
      s3Perms.addResources(`arn:${this.partition}:s3:::so0111-*`);
      inlinePolicy.addStatements(s3Perms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableCloudTrailToCloudWatchLogging
    //
    {
      const remediationName = 'EnableCloudTrailToCloudWatchLogging';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      // Role for CT->CW logging
      const ctcw_remediation_policy_statement_1 = new PolicyStatement();
      ctcw_remediation_policy_statement_1.addActions('logs:CreateLogStream');
      ctcw_remediation_policy_statement_1.effect = Effect.ALLOW;
      ctcw_remediation_policy_statement_1.addResources('arn:' + this.partition + ':logs:*:*:log-group:*');

      const ctcw_remediation_policy_statement_2 = new PolicyStatement();
      ctcw_remediation_policy_statement_2.addActions('logs:PutLogEvents');
      ctcw_remediation_policy_statement_2.effect = Effect.ALLOW;
      ctcw_remediation_policy_statement_2.addResources('arn:' + this.partition + ':logs:*:*:log-group:*:log-stream:*');

      const ctcw_remediation_policy_doc = new PolicyDocument();
      ctcw_remediation_policy_doc.addStatements(ctcw_remediation_policy_statement_1);
      ctcw_remediation_policy_doc.addStatements(ctcw_remediation_policy_statement_2);

      const ctcw_remediation_role = new Role(props.roleStack, 'ctcwremediationrole', {
        assumedBy: new ServicePrincipal(`cloudtrail.${this.urlSuffix}`),
        inlinePolicies: {
          default_lambdaPolicy: ctcw_remediation_policy_doc,
        },
        roleName: `${RESOURCE_PREFIX}-CloudTrailToCloudWatchLogs-${props.roleStack.getNamespace()}`,
      });
      ctcw_remediation_role.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
      {
        const childToMod = ctcw_remediation_role.node.findChild('Resource') as CfnRole;
        childToMod.cfnOptions.metadata = {
          cfn_nag: {
            rules_to_suppress: [
              {
                id: 'W28',
                reason: 'Static names chosen intentionally to provide integration in cross-account permissions',
              },
            ],
          },
        };
      }
      {
        const ctperms = new PolicyStatement();
        ctperms.addActions('cloudtrail:UpdateTrail', 'cloudtrail:GetTrail');

        ctperms.effect = Effect.ALLOW;
        ctperms.addResources('arn:' + this.partition + ':cloudtrail:*:' + this.account + ':trail/*');
        inlinePolicy.addStatements(ctperms);
      }
      {
        const s3perms = new PolicyStatement();
        s3perms.addActions('s3:GetBucketPolicy', 's3:PutBucketPolicy');
        s3perms.effect = Effect.ALLOW;
        s3perms.addResources('arn:' + this.partition + ':s3:::*');
        inlinePolicy.addStatements(s3perms);
      }
      {
        // Dependent permissions for cloudtrail:UpdateTrail
        const ctcwiam = new PolicyStatement();
        ctcwiam.addActions('iam:PassRole');
        ctcwiam.addResources(ctcw_remediation_role.roleArn);
        inlinePolicy.addStatements(ctcwiam);

        inlinePolicy.addStatements(iamGetRolePerms);
        inlinePolicy.addStatements(iamCreateServiceLinkedRolePerms);
        inlinePolicy.addStatements(iamServiceLinkedRolePolicyPerms);
        inlinePolicy.addStatements(denyPrivilegeEscalation);
        inlinePolicy.addStatements(orgListServiceAccessPerms);
      }
      {
        const cloudwatchLogsWrite = new PolicyStatement();
        cloudwatchLogsWrite.effect = Effect.ALLOW;
        cloudwatchLogsWrite.addActions('logs:CreateLogGroup');
        cloudwatchLogsWrite.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);
        inlinePolicy.addStatements(cloudwatchLogsWrite);

        const cloudwatchLogsRead = new PolicyStatement();
        cloudwatchLogsRead.effect = Effect.ALLOW;
        cloudwatchLogsRead.addActions('logs:DescribeLogGroups');
        cloudwatchLogsRead.addResources('*');
        inlinePolicy.addStatements(cloudwatchLogsRead);
      }

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      {
        const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
        childToMod.cfnOptions.metadata = {
          cfn_nag: {
            rules_to_suppress: [
              {
                id: 'W12',
                reason: 'Resource * is required for to allow creation and description of any log group',
              },
              {
                id: 'W28',
                reason: 'Static resource names are required to enable cross-account functionality',
              },
            ],
          },
        };
      }
      addCfnGuardSuppression(ctcw_remediation_role, 'IAM_NO_INLINE_POLICY_CHECK');
    }
    //-----------------------
    // EnableCloudTrailEncryption
    //
    {
      const remediationName = 'EnableCloudTrailEncryption';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const cloudtrailPerms = new PolicyStatement();
      cloudtrailPerms.addActions('cloudtrail:UpdateTrail');
      cloudtrailPerms.effect = Effect.ALLOW;
      cloudtrailPerms.addResources(`arn:${this.partition}:cloudtrail:*:${this.account}:trail/*`);
      inlinePolicy.addStatements(cloudtrailPerms);

      // Dependent permissions for cloudtrail:UpdateTrail
      inlinePolicy.addStatements(iamGetRolePerms);
      inlinePolicy.addStatements(iamCreateServiceLinkedRolePerms);
      inlinePolicy.addStatements(iamServiceLinkedRolePolicyPerms);
      inlinePolicy.addStatements(denyPrivilegeEscalation);
      inlinePolicy.addStatements(orgListServiceAccessPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation.',
            },
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide integration in cross-account permissions.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableDefaultEncryptionS3
    //
    {
      const remediationName = 'EnableDefaultEncryptionS3';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      inlinePolicy.addStatements(
        new PolicyStatement({
          actions: ['s3:PutEncryptionConfiguration', 'kms:GenerateDataKey'],
          resources: ['*'],
          effect: Effect.ALLOW,
        }),
      );
      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation.',
            },
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide integration in cross-account permissions.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableVPCFlowLogs
    //
    {
      const remediationName = 'EnableVPCFlowLogs';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      {
        const remediationPerms = new PolicyStatement();
        remediationPerms.addActions('ec2:CreateFlowLogs');
        remediationPerms.effect = Effect.ALLOW;
        remediationPerms.addResources(
          `arn:${this.partition}:ec2:*:${this.account}:vpc/*`,
          `arn:${this.partition}:ec2:*:${this.account}:vpc-flow-log/*`,
        );
        inlinePolicy.addStatements(remediationPerms);
      }
      {
        const iamPerms = new PolicyStatement();
        iamPerms.addActions('iam:PassRole');
        iamPerms.effect = Effect.ALLOW;
        iamPerms.addResources(
          `arn:${this.partition}:iam::${
            this.account
          }:role/${RESOURCE_PREFIX}-${remediationName}-remediationRole-${props.roleStack.getNamespace()}`,
        );
        inlinePolicy.addStatements(iamPerms);
      }
      {
        const ssmPerms = new PolicyStatement();
        ssmPerms.addActions('ssm:GetParameter');
        ssmPerms.effect = Effect.ALLOW;
        ssmPerms.addResources(
          `arn:${this.partition}:ssm:*:${this.account}:parameter/${RESOURCE_PREFIX}/CMK_REMEDIATION_ARN`,
        );
        inlinePolicy.addStatements(ssmPerms);
      }
      {
        const ec2ReadPerms = new PolicyStatement();
        ec2ReadPerms.addActions('ec2:DescribeFlowLogs', 'logs:DescribeLogGroups');
        ec2ReadPerms.effect = Effect.ALLOW;
        ec2ReadPerms.addResources('*');
        inlinePolicy.addStatements(ec2ReadPerms);
      }
      {
        const cloudwatchLogsCreatePerms = new PolicyStatement();
        cloudwatchLogsCreatePerms.addActions('logs:CreateLogGroup');
        cloudwatchLogsCreatePerms.effect = Effect.ALLOW;
        cloudwatchLogsCreatePerms.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);
        inlinePolicy.addStatements(cloudwatchLogsCreatePerms);
      }

      // Permissions for 'EnableVPCFlowLogs-remediationrole'
      const logGroupResourcePerms = new PolicyStatement();
      logGroupResourcePerms.effect = Effect.ALLOW;
      logGroupResourcePerms.addActions('logs:DescribeLogStreams', 'logs:CreateLogGroup');
      logGroupResourcePerms.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);

      const logStreamResourcePerms = new PolicyStatement();
      logStreamResourcePerms.effect = Effect.ALLOW;
      logStreamResourcePerms.addActions('logs:CreateLogStream', 'logs:PutLogEvents');
      logStreamResourcePerms.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*:log-stream:*`);

      const logGroupsReadPerms = new PolicyStatement();
      logGroupsReadPerms.effect = Effect.ALLOW;
      logGroupsReadPerms.addActions('logs:DescribeLogGroups');
      logGroupsReadPerms.addResources('*');

      const remediation_doc = new PolicyDocument();
      remediation_doc.addStatements(logGroupResourcePerms);
      remediation_doc.addStatements(logStreamResourcePerms);
      remediation_doc.addStatements(logGroupsReadPerms);

      const remediation_role = new Role(props.roleStack, 'EnableVPCFlowLogs-remediationrole', {
        assumedBy: new ServicePrincipal('vpc-flow-logs.amazonaws.com'),
        inlinePolicies: {
          default_lambdaPolicy: remediation_doc,
        },
        roleName: `${RESOURCE_PREFIX}-EnableVPCFlowLogs-remediationRole-${props.roleStack.getNamespace()}`,
      });
      remediation_role.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);

      const roleResource = remediation_role.node.findChild('Resource') as CfnRole;

      roleResource.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W11',
              reason: 'Resource * is required due to the administrative nature of the solution.',
            },
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide integration in cross-account permissions',
            },
          ],
        },
      };
      addCfnGuardSuppression(remediation_role, 'IAM_NO_INLINE_POLICY_CHECK');

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resources.',
            },
          ],
        },
      };
    }

    //-----------------------
    // CreateAccessLoggingBucket
    //
    {
      const remediationName = 'CreateAccessLoggingBucket';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const s3Perms = new PolicyStatement();
      s3Perms.addActions(
        's3:CreateBucket',
        's3:PutEncryptionConfiguration',
        's3:PutBucketAcl',
        's3:PutBucketOwnershipControls',
        's3:PutBucketPolicy',
      );
      s3Perms.effect = Effect.ALLOW;
      s3Perms.addResources(`arn:${this.partition}:s3:::so0111-*`);

      inlinePolicy.addStatements(s3Perms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resources.',
            },
          ],
        },
      };
    }

    //-----------------------
    // MakeEBSSnapshotsPrivate
    //
    {
      const remediationName = 'MakeEBSSnapshotsPrivate';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ec2ReadPerms = new PolicyStatement();
      ec2ReadPerms.addActions('ec2:DescribeSnapshots');
      ec2ReadPerms.effect = Effect.ALLOW;
      ec2ReadPerms.addResources('*');
      inlinePolicy.addStatements(ec2ReadPerms);

      const ec2SnapshotWritePerms = new PolicyStatement();
      ec2SnapshotWritePerms.addActions('ec2:ModifySnapshotAttribute');
      ec2SnapshotWritePerms.effect = Effect.ALLOW;
      ec2SnapshotWritePerms.addResources(`arn:${this.partition}:ec2:*::snapshot/*`);
      inlinePolicy.addStatements(ec2SnapshotWritePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* snapshot.',
            },
          ],
        },
      };
    }

    //-----------------------
    // MakeRDSSnapshotPrivate
    //
    {
      const remediationName = 'MakeRDSSnapshotPrivate';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const remediationPerms = new PolicyStatement();
      remediationPerms.addActions('rds:ModifyDBSnapshotAttribute', 'rds:ModifyDBClusterSnapshotAttribute');
      remediationPerms.effect = Effect.ALLOW;
      remediationPerms.addResources(
        `arn:${this.partition}:rds:*:${this.account}:snapshot:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster-snapshot:*`,
      );
      inlinePolicy.addStatements(remediationPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* snapshot.',
            },
          ],
        },
      };
    }

    //-----------------------
    // RemoveLambdaPublicAccess
    //
    {
      const remediationName = 'RemoveLambdaPublicAccess';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const lambdaPerms = new PolicyStatement();
      lambdaPerms.addActions('lambda:GetPolicy', 'lambda:RemovePermission');
      lambdaPerms.effect = Effect.ALLOW;
      lambdaPerms.addResources(`arn:${this.partition}:lambda:*:${this.account}:function:*`);
      inlinePolicy.addStatements(lambdaPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // RevokeUnrotatedKeys
    //
    {
      const remediationName = 'RevokeUnrotatedKeys';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'iam:UpdateAccessKey',
        'iam:ListAccessKeys',
        'iam:GetAccessKeyLastUsed',
        'iam:GetUser',
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources('arn:' + this.partition + ':iam::' + this.account + ':user/*');
      inlinePolicy.addStatements(remediationPolicy);

      const configPerms = new PolicyStatement();
      configPerms.addActions('config:ListDiscoveredResources');
      configPerms.effect = Effect.ALLOW;
      configPerms.addResources('*');
      inlinePolicy.addStatements(configPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // SetSSLBucketPolicy
    //
    {
      const remediationName = 'SetSSLBucketPolicy';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      {
        const remediationPerms = new PolicyStatement();
        remediationPerms.addActions('s3:GetBucketPolicy', 's3:PutBucketPolicy');
        remediationPerms.effect = Effect.ALLOW;
        remediationPerms.addResources(`arn:${this.partition}:s3:::*`);
        inlinePolicy.addStatements(remediationPerms);
      }

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
    }

    //-----------------------
    // ReplaceCodeBuildClearTextCredentials
    //
    {
      const remediationName = 'ReplaceCodeBuildClearTextCredentials';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'codeBuild:BatchGetProjects',
        'codeBuild:UpdateProject',
        'ssm:PutParameter',
        'iam:CreatePolicy',
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:codebuild:*:${this.account}:project/*`,
        `arn:${this.partition}:ssm:*:${this.account}:parameter/*`,
        `arn:${this.partition}:iam::${this.account}:policy/*`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      // CodeBuild projects are built by service roles
      const attachRolePolicy = new PolicyStatement();
      attachRolePolicy.addActions('iam:AttachRolePolicy');
      attachRolePolicy.addResources(`arn:${this.partition}:iam::${this.account}:role/service-role/*`);
      inlinePolicy.addStatements(attachRolePolicy);

      // Just in case, explicitly deny permission to modify our own role policy
      const attachRolePolicyDeny = new PolicyStatement();
      attachRolePolicyDeny.addActions('iam:AttachRolePolicy');
      attachRolePolicyDeny.effect = Effect.DENY;
      attachRolePolicyDeny.addResources(
        `arn:${this.partition}:iam::${
          this.account
        }:role/${remediationRoleNameBase}${remediationName}-${props.roleStack.getNamespace()}`,
      );
      inlinePolicy.addStatements(attachRolePolicyDeny);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }
    //----------------------------
    // S3BlockDenyList
    //
    {
      const remediationName = 'S3BlockDenylist';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('s3:PutBucketPolicy', 's3:GetBucketPolicy');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:s3:::*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }

    //-----------------------------------------
    // AWS-EncryptRdsSnapshot
    //
    {
      const remediationName = 'EncryptRDSSnapshot';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'rds:AddTagsToResource',
        'rds:CopyDBSnapshot',
        'rds:CopyDBClusterSnapshot',
        'rds:DescribeDBSnapshots',
        'rds:DescribeDBClusterSnapshots',
        'rds:DeleteDBSnapshot',
        'rds:DeleteDBClusterSnapshot',
        'rds:CopyCustomDBEngineVersion', // dependent permission for rds:CopyDBSnapshot
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:rds:*:${this.account}:snapshot:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster-snapshot:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster:*`,
        `arn:${this.partition}:rds:*:${this.account}:cev:*/*/*`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // DisablePublicAccessToRedshiftCluster
    //
    {
      const remediationName = 'DisablePublicAccessToRedshiftCluster';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const redshiftReadPerms = new PolicyStatement();
      redshiftReadPerms.addActions('redshift:DescribeClusters');
      redshiftReadPerms.effect = Effect.ALLOW;
      redshiftReadPerms.addResources('*');
      inlinePolicy.addStatements(redshiftReadPerms);

      const redshiftWritePerms = new PolicyStatement();
      redshiftWritePerms.addActions('redshift:ModifyCluster');
      redshiftWritePerms.effect = Effect.ALLOW;
      redshiftWritePerms.addResources(`arn:${this.partition}:redshift:*:${this.account}:cluster:*`);
      inlinePolicy.addStatements(redshiftWritePerms);

      // Dependent permissions for redshift:ModifyCluster
      inlinePolicy.addStatements(redshiftModifyClusterDependentPerms);
      inlinePolicy.addStatements(secretsManagerGetRandomPasswordPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableRedshiftClusterAuditLogging
    //
    {
      const remediationName = 'EnableRedshiftClusterAuditLogging';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('redshift:DescribeLoggingStatus', 'redshift:EnableLogging');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:redshift:*:${this.account}:cluster:*`);
      inlinePolicy.addStatements(remediationPolicy);
      remediationPolicy.addActions('s3:PutObject');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:s3:::*/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableAutomaticVersionUpgradeOnRedshiftCluster
    //
    {
      const remediationName = 'EnableAutomaticVersionUpgradeOnRedshiftCluster';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const redshiftReadPerms = new PolicyStatement();
      redshiftReadPerms.addActions('redshift:DescribeClusters');
      redshiftReadPerms.effect = Effect.ALLOW;
      redshiftReadPerms.addResources('*');
      inlinePolicy.addStatements(redshiftReadPerms);

      const redshiftWritePerms = new PolicyStatement();
      redshiftWritePerms.addActions('redshift:ModifyCluster');
      redshiftWritePerms.effect = Effect.ALLOW;
      redshiftWritePerms.addResources(`arn:${this.partition}:redshift:*:${this.account}:cluster:*`);
      inlinePolicy.addStatements(redshiftWritePerms);

      // Dependent permissions for redshift:ModifyCluster
      inlinePolicy.addStatements(redshiftModifyClusterDependentPerms);
      inlinePolicy.addStatements(secretsManagerGetRandomPasswordPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableAutomaticSnapshotsOnRedshiftCluster
    //
    {
      const remediationName = 'EnableAutomaticSnapshotsOnRedshiftCluster';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const redshiftReadPerms = new PolicyStatement();
      redshiftReadPerms.addActions('redshift:DescribeClusters');
      redshiftReadPerms.effect = Effect.ALLOW;
      redshiftReadPerms.addResources('*');
      inlinePolicy.addStatements(redshiftReadPerms);

      const redshiftWritePerms = new PolicyStatement();
      redshiftWritePerms.addActions('redshift:ModifyCluster');
      redshiftWritePerms.effect = Effect.ALLOW;
      redshiftWritePerms.addResources(`arn:${this.partition}:redshift:*:${this.account}:cluster:*`);
      inlinePolicy.addStatements(redshiftWritePerms);

      // Dependent permissions for redshift:ModifyCluster
      inlinePolicy.addStatements(redshiftModifyClusterDependentPerms);
      inlinePolicy.addStatements(secretsManagerGetRandomPasswordPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // CreateIAMSupportRole
    //
    {
      const remediationName = 'CreateIAMSupportRole';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const roleName = 'aws_incident_support_role';
      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole', 'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:TagRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(`arn:${this.partition}:iam::${this.account}:role/${roleName}`);
      inlinePolicy.addStatements(iamPerms);

      const denyAddPermsToSelf = new PolicyStatement();
      denyAddPermsToSelf.addActions('iam:AttachRolePolicy');
      denyAddPermsToSelf.effect = Effect.DENY;
      denyAddPermsToSelf.addResources(
        `arn:${this.partition}:iam::${
          this.account
        }:role/${remediationRoleNameBase}${remediationName}-${props.roleStack.getNamespace()}`,
      );
      inlinePolicy.addStatements(denyAddPermsToSelf);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation.',
            },
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide integration in cross-account permissions.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableEncryptionForSQSQueue
    //
    {
      const remediationName = 'EnableEncryptionForSQSQueue';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('sqs:GetQueueUrl', 'sqs:SetQueueAttributes', 'sqs:GetQueueAttributes');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:sqs:*:${this.account}:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // ConfigureSNSTopicForStack
    //
    {
      const remediationName = 'ConfigureSNSTopicForStack';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const cfnPerms = new PolicyStatement();
      cfnPerms.addActions('cloudformation:DescribeStacks', 'cloudformation:UpdateStack');
      cfnPerms.effect = Effect.ALLOW;
      cfnPerms.addResources(`arn:${this.partition}:cloudformation:*:${this.account}:stack/*/*`);
      inlinePolicy.addStatements(cfnPerms);

      // Dependent permissions for cloudformation:DescribeStacks
      const cfnDescribeStacksDependentPerms = new PolicyStatement();
      cfnDescribeStacksDependentPerms.addActions('cloudformation:ListStacks');
      cfnDescribeStacksDependentPerms.effect = Effect.ALLOW;
      cfnDescribeStacksDependentPerms.addResources('*');
      inlinePolicy.addStatements(cfnDescribeStacksDependentPerms);

      const snsPerms = new PolicyStatement();
      snsPerms.addActions('sns:CreateTopic', 'sns:Publish');
      snsPerms.effect = Effect.ALLOW;
      snsPerms.addResources(
        `arn:${this.partition}:sns:${this.region}:${this.account}:SO0111-ASR-CloudFormationNotifications`,
      );
      inlinePolicy.addStatements(snsPerms);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('servicecatalog:GetApplication');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:servicecatalog:*:${this.account}:/applications/*`);
      inlinePolicy.addStatements(remediationPolicy);

      inlinePolicy.addStatements(iamGetRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation.',
            },
          ],
        },
      };
    }

    //=========================================================================
    // The following are permissions only for use with AWS-owned documents that
    //   are available to GovCloud and China partition customers.
    //=========================================================================
    //-----------------------
    // AWS-ConfigureS3BucketLogging
    //
    {
      const remediationName = 'ConfigureS3BucketLogging';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const s3Perms = new PolicyStatement();
      s3Perms.addActions('s3:PutBucketLogging', 's3:CreateBucket', 's3:PutEncryptionConfiguration', 's3:PutBucketAcl');
      s3Perms.effect = Effect.ALLOW;
      s3Perms.addResources(`arn:${this.partition}:s3:::*`);

      inlinePolicy.addStatements(s3Perms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }
    //-----------------------------------------
    // AWS-DisablePublicAccessForSecurityGroup
    //
    {
      const remediationName = 'DisablePublicAccessForSecurityGroup';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const securityGroupsListPerms = new PolicyStatement();
      securityGroupsListPerms.addActions('ec2:DescribeSecurityGroups');
      securityGroupsListPerms.effect = Effect.ALLOW;
      securityGroupsListPerms.addResources('*');
      inlinePolicy.addStatements(securityGroupsListPerms);

      const securityGroupResourcePerms = new PolicyStatement();
      securityGroupResourcePerms.addActions(
        'ec2:RevokeSecurityGroupIngress',
        'ec2:UpdateSecurityGroupRuleDescriptionsEgress',
        'ec2:DescribeSecurityGroupReferences',
        'ec2:RevokeSecurityGroupEgress',
        'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
      );
      securityGroupResourcePerms.effect = Effect.ALLOW;
      securityGroupResourcePerms.addResources(`arn:${this.partition}:ec2:*:${this.account}:security-group/*`);
      inlinePolicy.addStatements(securityGroupResourcePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
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
      const remediationName = 'ConfigureS3BucketPublicAccessBlock';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('s3:PutBucketPublicAccessBlock', 's3:GetBucketPublicAccessBlock');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:s3:::*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // AWSConfigRemediation-ConfigureS3PublicAccessBlock
    //
    {
      const remediationName = 'ConfigureS3PublicAccessBlock';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('s3:PutAccountPublicAccessBlock', 's3:GetAccountPublicAccessBlock');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources('*');
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // AWSConfigRemediation-EnableCloudTrailLogFileValidation
    //
    {
      const remediationName = 'EnableCloudTrailLogFileValidation';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('cloudtrail:UpdateTrail', 'cloudtrail:GetTrail');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources('arn:' + this.partition + ':cloudtrail:*:' + this.account + ':trail/*');
      inlinePolicy.addStatements(remediationPolicy);

      // Dependent permissions for cloudtrail:UpdateTrail
      const iamPassRolePerms = new PolicyStatement();
      iamPassRolePerms.addActions('iam:PassRole');
      iamPassRolePerms.effect = Effect.ALLOW;
      iamPassRolePerms.addResources(
        `arn:${this.partition}:iam::${this.account}:role/aws-service-role/cloudtrail.amazonaws.com/AWSServiceRoleForCloudTrail`,
      );

      inlinePolicy.addStatements(iamGetRolePerms);
      inlinePolicy.addStatements(iamCreateServiceLinkedRolePerms);
      inlinePolicy.addStatements(iamServiceLinkedRolePolicyPerms);
      inlinePolicy.addStatements(denyPrivilegeEscalation);
      inlinePolicy.addStatements(orgListServiceAccessPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
    }

    //-----------------------
    // AWSConfigRemediation-EnableEbsEncryptionByDefault
    //
    {
      const remediationName = 'EnableEbsEncryptionByDefault';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const ec2Perms = new PolicyStatement();
      ec2Perms.addActions('ec2:EnableEBSEncryptionByDefault', 'ec2:GetEbsEncryptionByDefault');
      ec2Perms.effect = Effect.ALLOW;
      ec2Perms.addResources('*');
      inlinePolicy.addStatements(ec2Perms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-EnableEnhancedMonitoringOnRDSInstance
    //
    {
      const remediationName = 'EnableEnhancedMonitoringOnRDSInstance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      {
        const iamPerms = new PolicyStatement();
        iamPerms.addActions('iam:GetRole', 'iam:PassRole');
        iamPerms.effect = Effect.ALLOW;
        iamPerms.addResources(
          `arn:${this.partition}:iam::${
            this.account
          }:role/${RESOURCE_PREFIX}-RDSMonitoring-remediationRole-${props.roleStack.getNamespace()}`,
        );
        inlinePolicy.addStatements(iamPerms);
      }
      {
        const rdsPerms = new PolicyStatement();
        rdsPerms.addActions('rds:DescribeDBInstances', 'rds:ModifyDBInstance');
        rdsPerms.effect = Effect.ALLOW;
        rdsPerms.addResources(
          `arn:${this.partition}:rds:*:${this.account}:db:*`,
          `arn:${this.partition}:rds:*:${this.account}:og:*`,
          `arn:${this.partition}:rds:*:${this.account}:pg:*`,
          `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
          `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
        );
        inlinePolicy.addStatements(rdsPerms);

        // Dependent permissions for rds:ModifyDBInstance
        inlinePolicy.addStatements(rdsDependentPerms);
        inlinePolicy.addStatements(rdsDependentIamRolePerms);
      }

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* RDS database.',
            },
          ],
        },
      };

      new Rds6EnhancedMonitoringRole(props.roleStack, 'Rds6EnhancedMonitoringRole', {
        roleName: `${RESOURCE_PREFIX}-RDSMonitoring-remediationRole-${props.roleStack.getNamespace()}`,
      });
    }
    //-----------------------
    // AWSConfigRemediation-EnableKeyRotation
    //
    {
      const remediationName = 'EnableKeyRotation';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const remediationPerms = new PolicyStatement();
      remediationPerms.addActions('kms:EnableKeyRotation', 'kms:GetKeyRotationStatus');
      remediationPerms.effect = Effect.ALLOW;
      remediationPerms.addResources(`arn:${this.partition}:kms:*:${this.account}:key/*`);
      inlinePolicy.addStatements(remediationPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-EnableRDSClusterDeletionProtection
    //
    {
      const remediationName = 'EnableRDSClusterDeletionProtection';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const configPerms = new PolicyStatement();
      configPerms.addActions('config:GetResourceConfigHistory');
      configPerms.effect = Effect.ALLOW;
      configPerms.addResources('*');
      inlinePolicy.addStatements(configPerms);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBClusters', 'rds:ModifyDBCluster', 'rds:ModifyDBInstance');
      rdsPerms.effect = Effect.ALLOW;
      rdsPerms.addResources(
        `arn:${this.partition}:rds:*:${this.account}:pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:og:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster-pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
        `arn:${this.partition}:rds:*:${this.account}:db:*`,
        `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
      );
      inlinePolicy.addStatements(rdsPerms);

      // Dependent permissions for rds:ModifyDBInstance & rds:ModifyDBCluster
      inlinePolicy.addStatements(rdsDependentPerms);
      inlinePolicy.addStatements(rdsDependentIamRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* RDS database.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSCluster
    //
    {
      const remediationName = 'EnableCopyTagsToSnapshotOnRDSCluster';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const configPerms = new PolicyStatement();
      configPerms.addActions('config:GetResourceConfigHistory');
      configPerms.effect = Effect.ALLOW;
      configPerms.addResources('*');
      inlinePolicy.addStatements(configPerms);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBClusters', 'rds:ModifyDBCluster');
      rdsPerms.effect = Effect.ALLOW;
      rdsPerms.addResources(
        `arn:${this.partition}:rds:*:${this.account}:pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:og:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster-pg:*`,
      );
      inlinePolicy.addStatements(rdsPerms);

      // Dependent permissions for rds:ModifyDBCluster
      inlinePolicy.addStatements(rdsDependentPerms);
      inlinePolicy.addStatements(rdsDependentIamRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* RDS database.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableRDSInstanceDeletionProtection
    //
    {
      const remediationName = 'EnableRDSInstanceDeletionProtection';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBInstances', 'rds:ModifyDBInstance');
      rdsPerms.addResources(
        `arn:${this.partition}:rds:*:${this.account}:db:*`,
        `arn:${this.partition}:rds:*:${this.account}:og:*`,
        `arn:${this.partition}:rds:*:${this.account}:pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
        `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
      );
      inlinePolicy.addStatements(rdsPerms);

      // Dependent permissions for rds:ModifyDBInstance
      inlinePolicy.addStatements(rdsDependentPerms);
      inlinePolicy.addStatements(rdsDependentIamRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* RDS database.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableMultiAZOnRDSInstance
    //
    {
      const remediationName = 'EnableMultiAZOnRDSInstance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBInstances', 'rds:ModifyDBInstance');
      rdsPerms.addResources(
        `arn:${this.partition}:rds:*:${this.account}:db:*`,
        `arn:${this.partition}:rds:*:${this.account}:og:*`,
        `arn:${this.partition}:rds:*:${this.account}:pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
        `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
      );
      inlinePolicy.addStatements(rdsPerms);

      // Dependent permissions for rds:ModifyDBInstance
      inlinePolicy.addStatements(rdsDependentPerms);
      inlinePolicy.addStatements(rdsDependentIamRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for *any* RDS database.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules
    //
    {
      const remediationName = 'RemoveVPCDefaultSecurityGroupRules';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ec2SecurityGroupResourcePerms = new PolicyStatement();
      ec2SecurityGroupResourcePerms.addActions(
        'ec2:UpdateSecurityGroupRuleDescriptionsEgress',
        'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
        'ec2:RevokeSecurityGroupIngress',
        'ec2:RevokeSecurityGroupEgress',
        'ec2:DescribeSecurityGroupReferences',
      );
      ec2SecurityGroupResourcePerms.effect = Effect.ALLOW;
      ec2SecurityGroupResourcePerms.addResources(
        'arn:' + this.partition + ':ec2:*:' + this.account + ':security-group/*',
      );

      const ec2ListSecurityGroupsPerms = new PolicyStatement();
      ec2ListSecurityGroupsPerms.addActions('ec2:DescribeSecurityGroups');
      ec2ListSecurityGroupsPerms.effect = Effect.ALLOW;
      ec2ListSecurityGroupsPerms.addResources('*');

      inlinePolicy.addStatements(ec2SecurityGroupResourcePerms, ec2ListSecurityGroupsPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide integration in cross-account permissions',
            },
          ],
        },
      };
    }
    //-----------------------
    // AWSConfigRemediation-RevokeUnusedIAMUserCredentials
    //
    {
      const remediationName = 'RevokeUnusedIAMUserCredentials';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'iam:UpdateAccessKey',
        'iam:ListAccessKeys',
        'iam:GetAccessKeyLastUsed',
        'iam:GetUser',
        'iam:GetLoginProfile',
        'iam:DeleteLoginProfile',
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources('arn:' + this.partition + ':iam::' + this.account + ':user/*');
      inlinePolicy.addStatements(remediationPolicy);

      const cfgPerms = new PolicyStatement();
      cfgPerms.addActions('config:ListDiscoveredResources');
      cfgPerms.effect = Effect.ALLOW;
      cfgPerms.addResources('*');
      inlinePolicy.addStatements(cfgPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // AWSConfigRemediation-SetIAMPasswordPolicy
    //
    {
      const remediationName = 'SetIAMPasswordPolicy';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const iamResourcePerms = new PolicyStatement();
      iamResourcePerms.addActions('iam:UpdateAccountPasswordPolicy', 'iam:GetAccountPasswordPolicy');
      iamResourcePerms.effect = Effect.ALLOW;
      iamResourcePerms.addResources('*');
      inlinePolicy.addStatements(iamResourcePerms);

      const ec2ResourcePerms = new PolicyStatement();
      ec2ResourcePerms.addActions(
        'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
        'ec2:RevokeSecurityGroupIngress',
        'ec2:RevokeSecurityGroupEgress',
      );
      ec2ResourcePerms.effect = Effect.ALLOW;
      ec2ResourcePerms.addResources(`arn:${this.partition}:ec2:*:${this.account}:security-group/*`);
      inlinePolicy.addStatements(ec2ResourcePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-DisablePublicAccessToRDSInstance
    //
    {
      const remediationName = 'DisablePublicAccessToRDSInstance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBInstances', 'rds:ModifyDBInstance');
      rdsPerms.addResources(
        `arn:${this.partition}:rds:*:${this.account}:db:*`,
        `arn:${this.partition}:rds:*:${this.account}:og:*`,
        `arn:${this.partition}:rds:*:${this.account}:pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
        `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
      );
      inlinePolicy.addStatements(rdsPerms);

      // Dependent permissions for rds:ModifyDBInstance
      inlinePolicy.addStatements(rdsDependentPerms);
      inlinePolicy.addStatements(rdsDependentIamRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-EnableMinorVersionUpgradeOnRDSDBInstance
    //
    {
      const remediationName = 'EnableMinorVersionUpgradeOnRDSDBInstance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'rds:DescribeDBInstances',
        'rds:ModifyDBInstance',
        'rds:DescribeDBClusters',
        'rds:ModifyDBCluster',
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:rds:*:${this.account}:pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:og:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster:*`,
        `arn:${this.partition}:rds:*:${this.account}:cluster-pg:*`,
        `arn:${this.partition}:rds:*:${this.account}:secgrp:*`,
        `arn:${this.partition}:rds:*:${this.account}:db:*`,
        `arn:${this.partition}:rds:*:${this.account}:subgrp:*`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      // Dependent permissions for rds:ModifyDBCluster & rds:ModifyDBInstance
      inlinePolicy.addStatements(rdsDependentPerms);
      inlinePolicy.addStatements(rdsDependentIamRolePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // AWSConfigRemediation-EncryptSNSTopic
    //
    {
      const remediationName = 'EnableEncryptionForSNSTopic';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('sns:SetTopicAttributes', 'sns:GetTopicAttributes');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:sns:*:${this.account}:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableDeliveryStatusLoggingForSNSTopic
    //
    {
      const remediationName = 'EnableDeliveryStatusLoggingForSNSTopic';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('sns:SetTopicAttributes', 'sns:GetTopicAttributes');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:sns:*:${this.account}:*`);
      inlinePolicy.addStatements(remediationPolicy);

      const sns2Role = new SNS2DeliveryStatusLoggingRole(props.roleStack, 'SNS2DeliveryStatusLoggingRole', {
        roleName: `${RESOURCE_PREFIX}-SNS2DeliveryStatusLogging-remediationRole-${props.roleStack.getNamespace()}`,
      });

      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole', 'iam:PassRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(sns2Role.roleArn);
      inlinePolicy.addStatements(iamPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // DisablePublicIPAutoAssign
    //
    {
      const remediationName = 'DisablePublicIPAutoAssign';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ec2SubnetsReadPerms = new PolicyStatement();
      ec2SubnetsReadPerms.addActions('ec2:DescribeSubnets');
      ec2SubnetsReadPerms.effect = Effect.ALLOW;
      ec2SubnetsReadPerms.addResources('*');
      inlinePolicy.addStatements(ec2SubnetsReadPerms);

      const ec2SubnetsWritePerms = new PolicyStatement();
      ec2SubnetsWritePerms.addActions('ec2:ModifySubnetAttribute');
      ec2SubnetsWritePerms.effect = Effect.ALLOW;
      ec2SubnetsWritePerms.addResources(`arn:${this.partition}:ec2:*:${this.account}:subnet/*`);
      inlinePolicy.addStatements(ec2SubnetsWritePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableIMDSV2OnInstance
    //
    {
      const remediationName = 'EnableIMDSV2OnInstance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ec2ReadPerms = new PolicyStatement();
      ec2ReadPerms.addActions('ec2:DescribeInstances');
      ec2ReadPerms.effect = Effect.ALLOW;
      ec2ReadPerms.addResources('*');
      inlinePolicy.addStatements(ec2ReadPerms);

      const ec2WritePerms = new PolicyStatement();
      ec2WritePerms.addActions('ec2:ModifyInstanceMetadataOptions');
      ec2WritePerms.effect = Effect.ALLOW;
      ec2WritePerms.addResources(`arn:${this.partition}:ec2:*:${this.account}:instance/*`);
      inlinePolicy.addStatements(ec2WritePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // RemoveCodeBuildPrivilegedMode
    //
    {
      const remediationName = 'RemoveCodeBuildPrivilegedMode';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('codebuild:BatchGetProjects', 'codebuild:UpdateProject');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:codebuild:*:${this.account}:project/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableCloudFrontDefaultRootObject
    //
    {
      const remediationName = 'EnableCloudFrontDefaultRootObject';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('cloudfront:GetDistributionConfig', 'cloudfront:UpdateDistribution');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:cloudfront::${this.account}:distribution/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // BlockSSMDocumentPublicAccess
    //
    {
      const remediationName = 'BlockSSMDocumentPublicAccess';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ssm:DescribeDocumentPermission', 'ssm:ModifyDocumentPermission');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:ssm:*:${this.account}:document/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableSSMDocumentBlockPublicSharing
    //
    {
      const remediationName = 'EnableSSMDocumentBlockPublicSharing';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ssm:GetServiceSetting', 'ssm:UpdateServiceSetting');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:ssm:*:${this.account}:servicesetting/ssm/documents/console/public-sharing-permission`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
    }

    //-----------------------
    // AttachSSMPermissionsToEC2
    //
    {
      const remediationName = 'AttachSSMPermissionsToEC2';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const passRoleIAMPolicy = new PolicyStatement();
      passRoleIAMPolicy.addActions('iam:PassRole');
      passRoleIAMPolicy.effect = Effect.ALLOW;
      passRoleIAMPolicy.addResources(
        `arn:${this.partition}:iam::${
          this.account
        }:role/${RESOURCE_PREFIX}-AttachSSMPermissionsToEC2-RemediationRole-${props.roleStack.getNamespace()}`,
      );
      inlinePolicy.addStatements(passRoleIAMPolicy);

      const iamReadPolicy = new PolicyStatement();
      iamReadPolicy.addActions(
        'iam:GetRole',
        'iam:GetInstanceProfile',
        'iam:ListAttachedRolePolicies',
        'iam:ListRolePolicies',
      );
      iamReadPolicy.effect = Effect.ALLOW;
      iamReadPolicy.addResources(
        `arn:${this.partition}:iam::${this.account}:role/*`,
        `arn:${this.partition}:iam::${this.account}:instance-profile/*`,
      );
      inlinePolicy.addStatements(iamReadPolicy);

      const attachRolePolicyRestricted = new PolicyStatement();
      attachRolePolicyRestricted.addActions('iam:AttachRolePolicy');
      attachRolePolicyRestricted.effect = Effect.ALLOW;
      attachRolePolicyRestricted.addResources(`arn:${this.partition}:iam::${this.account}:role/*`);
      attachRolePolicyRestricted.addCondition('StringEquals', {
        'iam:PolicyARN': `arn:${this.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore`,
      });
      inlinePolicy.addStatements(attachRolePolicyRestricted);

      const addRoleToProfilePolicy = new PolicyStatement();
      addRoleToProfilePolicy.addActions('iam:AddRoleToInstanceProfile');
      addRoleToProfilePolicy.effect = Effect.ALLOW;
      addRoleToProfilePolicy.addResources(`arn:${this.partition}:iam::${this.account}:instance-profile/*`);
      inlinePolicy.addStatements(addRoleToProfilePolicy);

      // Split EC2 permissions by resource scope
      const ec2DescribePermissions = new PolicyStatement();
      ec2DescribePermissions.addActions(
        'ec2:DescribeIamInstanceProfileAssociations',
        'ec2:DescribeInstanceStatus',
        'ec2:DescribeInstances',
      );
      ec2DescribePermissions.effect = Effect.ALLOW;
      ec2DescribePermissions.addResources('*'); // These describe operations require * resource
      inlinePolicy.addStatements(ec2DescribePermissions);

      const ec2ModifyPermissions = new PolicyStatement();
      ec2ModifyPermissions.addActions('ec2:AssociateIamInstanceProfile');
      ec2ModifyPermissions.effect = Effect.ALLOW;
      ec2ModifyPermissions.addResources(`arn:${this.partition}:ec2:*:${this.account}:instance/*`);
      inlinePolicy.addStatements(ec2ModifyPermissions);

      // Add protection against permission mutation on own role
      const denyPermissionMutation = new PolicyStatement();
      denyPermissionMutation.addActions(...PRIVILEGE_ESCALATION_ACTIONS);
      denyPermissionMutation.effect = Effect.DENY;
      denyPermissionMutation.addResources(
        `arn:${this.partition}:iam::${
          this.account
        }:role/${remediationRoleNameBase}${remediationName}-${props.roleStack.getNamespace()}`,
      );
      inlinePolicy.addStatements(denyPermissionMutation);
      inlinePolicy.addStatements(denyPrivilegeEscalation);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required to allow remediation of any EC2 instances.',
            },
          ],
        },
      };

      // IAM role for SSM.1 remediation, designed to be attached to EC2 instances for Systems Manager access
      const attachSSMPermissionsToEC2RemediationRole = new Role(
        props.roleStack,
        'AttachSSMPermissionsToEC2-remediationrole',
        {
          assumedBy: new ServicePrincipal('ec2.amazonaws.com'),
          managedPolicies: [ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')],
          roleName: `${RESOURCE_PREFIX}-AttachSSMPermissionsToEC2-RemediationRole-${props.roleStack.getNamespace()}`,
        },
      );
      attachSSMPermissionsToEC2RemediationRole.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
      addCfnGuardSuppression(attachSSMPermissionsToEC2RemediationRole, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

      // Instance Profile for SSM.1 remediation, designed to be attached to EC2 instances for Systems Manager access
      const attachSSMPermissionsToEC2InstanceProfile = new InstanceProfile(
        props.roleStack,
        'AttachSSMPermissionsToEC2-instanceprofile',
        {
          instanceProfileName: `${RESOURCE_PREFIX}-AttachSSMPermissionsToEC2-InstanceProfile-${props.roleStack.getNamespace()}`,
          role: attachSSMPermissionsToEC2RemediationRole,
        },
      );
      attachSSMPermissionsToEC2InstanceProfile.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
    }

    //-----------------------
    // AttachServiceVPCEndpoint
    //
    {
      const remediationName = 'AttachServiceVPCEndpoint';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const vpcEndpointPolicy = new PolicyStatement();
      vpcEndpointPolicy.addActions('ec2:CreateVpcEndpoint', 'ec2:DescribeVpcAttribute');
      vpcEndpointPolicy.effect = Effect.ALLOW;
      vpcEndpointPolicy.addResources(
        `arn:${this.partition}:ec2:*:${this.account}:vpc/*`,
        `arn:${this.partition}:ec2:*:${this.account}:vpc-endpoint/*`,
        `arn:${this.partition}:ec2:*:${this.account}:subnet/*`,
        `arn:${this.partition}:ec2:*:${this.account}:security-group/*`,
        `arn:${this.partition}:ec2:*:${this.account}:route-table/*`,
      );
      inlinePolicy.addStatements(vpcEndpointPolicy);

      const route53Policy = new PolicyStatement();
      route53Policy.addActions('route53:AssociateVPCWithHostedZone');
      route53Policy.effect = Effect.ALLOW;
      route53Policy.addResources(`arn:${this.partition}:route53:::hostedzone/*`);
      inlinePolicy.addStatements(route53Policy);

      const vpcSubnetPolicy = new PolicyStatement();
      vpcSubnetPolicy.addActions('ec2:DescribeSubnets', 'ec2:DescribeVpcs');
      vpcSubnetPolicy.effect = Effect.ALLOW;
      vpcSubnetPolicy.addResources('*');
      inlinePolicy.addStatements(vpcSubnetPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required to list all VPC subnets.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableBucketEventNotifications
    //
    {
      const remediationName = 'EnableBucketEventNotifications';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        's3:GetBucketNotification',
        's3:PutBucketNotification',
        'sns:CreateTopic',
        'sns:GetTopicAttributes',
        'sns:SetTopicAttributes',
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:sns:*:${this.account}:*`, `arn:${this.partition}:s3:::*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // ConfigureDynamoDBAutoScaling
    //
    {
      const remediationName = 'ConfigureDynamoDBAutoScaling';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'application-autoscaling:RegisterScalableTarget',
        'application-autoscaling:PutScalingPolicy',
        'application-autoscaling:TagResource',
      );
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:application-autoscaling:*:${this.account}:scalable-target/*`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // EnableDynamoDBDeletionProtection
    //
    {
      const remediationName = 'EnableDynamoDBDeletionProtection';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('dynamodb:UpdateTable');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:dynamodb:*:${this.account}:table/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // EnableElastiCacheBackups
    //
    {
      const remediationName = 'EnableElastiCacheBackups';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const clusterPolicy = new PolicyStatement();
      clusterPolicy.addActions('elasticache:ModifyCacheCluster');
      clusterPolicy.effect = Effect.ALLOW;
      clusterPolicy.addResources(`arn:${this.partition}:elasticache:*:${this.account}:cluster:*`);
      inlinePolicy.addStatements(clusterPolicy);

      const replicationGroupPolicy = new PolicyStatement();
      replicationGroupPolicy.addActions('elasticache:ModifyReplicationGroup', 'elasticache:DescribeReplicationGroups');
      replicationGroupPolicy.effect = Effect.ALLOW;
      replicationGroupPolicy.addResources(`arn:${this.partition}:elasticache:*:${this.account}:replicationgroup:*`);
      inlinePolicy.addStatements(replicationGroupPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // EnforceHTTPSForALB
    //
    {
      const remediationName = 'EnforceHTTPSForALB';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const elbV2ListenerReadPerms = new PolicyStatement();
      elbV2ListenerReadPerms.addActions('elasticloadbalancing:DescribeListeners');
      elbV2ListenerReadPerms.effect = Effect.ALLOW;
      elbV2ListenerReadPerms.addResources('*');
      inlinePolicy.addStatements(elbV2ListenerReadPerms);

      const elbV2ListenerWritePerms = new PolicyStatement();
      elbV2ListenerWritePerms.addActions(
        'elasticloadbalancing:CreateListener',
        'elasticloadbalancing:AddTags',
        'elasticloadbalancing:ModifyListener',
      );
      elbV2ListenerWritePerms.effect = Effect.ALLOW;
      elbV2ListenerWritePerms.addResources(
        `arn:${this.partition}:elasticloadbalancing:*:${this.account}:listener-rule/app/*/*/*/*`,
        `arn:${this.partition}:elasticloadbalancing:*:${this.account}:listener/app/*/*/*`,
        `arn:${this.partition}:elasticloadbalancing:*:${this.account}:loadbalancer/app/*/*`,
        `arn:${this.partition}:elasticloadbalancing:*:${this.account}:targetgroup/*/*`,
      );
      inlinePolicy.addStatements(elbV2ListenerWritePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // LimitECSRootFilesystemAccess
    //
    {
      const remediationName = 'LimitECSRootFilesystemAccess';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ecsRegisterTaskDefinitionPolicy = new PolicyStatement();
      ecsRegisterTaskDefinitionPolicy.addActions('ecs:RegisterTaskDefinition');
      ecsRegisterTaskDefinitionPolicy.effect = Effect.ALLOW;
      ecsRegisterTaskDefinitionPolicy.addResources(`arn:${this.partition}:ecs:*:${this.account}:task-definition/*:*`);
      inlinePolicy.addStatements(ecsRegisterTaskDefinitionPolicy);

      const ecsDescribeTaskDefinitionPolicy = new PolicyStatement();
      ecsDescribeTaskDefinitionPolicy.addActions('ecs:DescribeTaskDefinition');
      ecsDescribeTaskDefinitionPolicy.effect = Effect.ALLOW;
      ecsDescribeTaskDefinitionPolicy.addResources('*');
      inlinePolicy.addStatements(ecsDescribeTaskDefinitionPolicy);

      const iamPermissionsPolicy = new PolicyStatement();
      iamPermissionsPolicy.addActions('iam:PassRole');
      iamPermissionsPolicy.effect = Effect.ALLOW;
      iamPermissionsPolicy.addResources(
        `arn:${this.partition}:iam::${this.account}:role/ecsTaskExecutionRole`,
        `arn:${this.partition}:iam::${this.account}:role/*TaskExecutionRole*`,
        `arn:${this.partition}:iam::${this.account}:role/*TaskRole*`,
      );
      iamPermissionsPolicy.addCondition('StringEquals', {
        'iam:PassedToService': 'ecs-tasks.amazonaws.com',
      });
      inlinePolicy.addStatements(iamPermissionsPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // EnableElastiCacheReplicationGroupFailover
    //
    {
      const remediationName = 'EnableElastiCacheReplicationGroupFailover';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const replicationGroupPolicy = new PolicyStatement();
      replicationGroupPolicy.addActions('elasticache:ModifyReplicationGroup');
      replicationGroupPolicy.effect = Effect.ALLOW;
      replicationGroupPolicy.addResources(`arn:${this.partition}:elasticache:*:${this.account}:replicationgroup:*`);
      inlinePolicy.addStatements(replicationGroupPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // EnableElastiCacheVersionUpgrades
    //
    {
      const remediationName = 'EnableElastiCacheVersionUpgrades';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('elasticache:ModifyCacheCluster');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:elasticache:*:${this.account}:cluster:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // AWSConfigRemediation-SetCloudFrontOriginDomain
    //
    {
      const remediationName = 'SetCloudFrontOriginDomain';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('cloudfront:UpdateDistribution', 'cloudfront:GetDistributionConfig');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources('arn:' + this.partition + ':cloudfront::' + this.account + ':distribution/*');
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // DisableUnrestrictedAccessToHighRiskPorts
    //
    {
      const remediationName = 'DisableUnrestrictedAccessToHighRiskPorts';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      inlinePolicy.addStatements(ec2DescribeSecurityGroupRulesPerms);

      inlinePolicy.addStatements(ec2SecurityGroupRevokeIngressPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnablePrivateRepositoryScanning
    //
    {
      const remediationName = 'EnablePrivateRepositoryScanning';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ecr:PutImageScanningConfiguration');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:ecr:*:${this.account}:repository/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // SetS3LifecyclePolicy
    //
    {
      const remediationName = 'SetS3LifecyclePolicy';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('s3:PutLifecycleConfiguration', 's3:GetLifecycleConfiguration');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:s3:::*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // UpdateSecretRotationPeriod
    //
    {
      const remediationName = 'UpdateSecretRotationPeriod';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('secretsmanager:RotateSecret', 'secretsmanager:DescribeSecret');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:secretsmanager:*:${this.account}:secret:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // DisableTGWAutoAcceptSharedAttachments
    //
    {
      const remediationName = 'DisableTGWAutoAcceptSharedAttachments';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ec2TransitGatewayReadPerms = new PolicyStatement();
      ec2TransitGatewayReadPerms.addActions('ec2:DescribeTransitGateways');
      ec2TransitGatewayReadPerms.effect = Effect.ALLOW;
      ec2TransitGatewayReadPerms.addResources('*');
      inlinePolicy.addStatements(ec2TransitGatewayReadPerms);

      const ec2TransitGatewayWritePerms = new PolicyStatement();
      ec2TransitGatewayWritePerms.addActions('ec2:ModifyTransitGateway');
      ec2TransitGatewayWritePerms.effect = Effect.ALLOW;
      ec2TransitGatewayWritePerms.addResources(
        `arn:${this.partition}:ec2:*:${this.account}:transit-gateway/*`,
        `arn:${this.partition}:ec2:*:${this.account}:transit-gateway-route-table/*`,
      );
      inlinePolicy.addStatements(ec2TransitGatewayWritePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableGuardDuty
    //
    {
      const remediationName = 'EnableGuardDuty';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const guardDutyWildcardPerms = new PolicyStatement();
      guardDutyWildcardPerms.addActions('guardduty:ListDetectors', 'guardduty:CreateDetector');
      guardDutyWildcardPerms.effect = Effect.ALLOW;
      guardDutyWildcardPerms.addResources('*');
      inlinePolicy.addStatements(guardDutyWildcardPerms);

      const guardDutyDetectorResourcePerms = new PolicyStatement();
      guardDutyDetectorResourcePerms.addActions('guardduty:UpdateDetector', 'guardduty:GetDetector');
      guardDutyDetectorResourcePerms.effect = Effect.ALLOW;
      guardDutyDetectorResourcePerms.addResources(`arn:${this.partition}:guardduty:*:${this.account}:detector/*`);
      inlinePolicy.addStatements(guardDutyDetectorResourcePerms);

      const guardDutyServiceLinkedRolePerms = new PolicyStatement();
      guardDutyServiceLinkedRolePerms.addActions(
        'iam:CreateServiceLinkedRole',
        'iam:PutRolePolicy',
        'iam:DeleteRolePolicy',
      );
      guardDutyServiceLinkedRolePerms.effect = Effect.ALLOW;
      guardDutyServiceLinkedRolePerms.addResources(
        `arn:${this.partition}:iam::${this.account}:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty`,
      );
      inlinePolicy.addStatements(guardDutyServiceLinkedRolePerms);

      // Add protection against permission mutation on own role
      const denyPermissionMutation = new PolicyStatement();
      denyPermissionMutation.addActions(...PRIVILEGE_ESCALATION_ACTIONS);
      denyPermissionMutation.effect = Effect.DENY;
      denyPermissionMutation.addResources(
        `arn:${this.partition}:iam::${
          this.account
        }:role/${remediationRoleNameBase}${remediationName}-${props.roleStack.getNamespace()}`,
      );
      inlinePolicy.addStatements(denyPermissionMutation);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }

    //-----------------------
    // TagDynamoDBTableResource
    //
    {
      const remediationName = 'TagDynamoDBTableResource';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('dynamodb:TagResource');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:dynamodb:*:${this.account}:table/*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      addCfnGuardSuppression(inlinePolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    }

    //-----------------------
    // TagGuardDutyResource
    //
    {
      const remediationName = 'TagGuardDutyResource';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('guardduty:TagResource');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:guardduty:*:*:detector/*/filter/*`,
        `arn:${this.partition}:guardduty:*:*:detector/*`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableAutoSecretRotation
    //
    {
      const remediationName = 'EnableAutoSecretRotation';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('secretsmanager:RotateSecret', 'secretsmanager:DescribeSecret');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:secretsmanager:*:${this.account}:secret:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // RevokeUnauthorizedInboundRules
    //
    {
      const remediationName = 'RevokeUnauthorizedInboundRules';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      inlinePolicy.addStatements(ec2DescribeSecurityGroupRulesPerms);
      inlinePolicy.addStatements(ec2SecurityGroupRevokeIngressPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // RemoveUnusedSecret
    //
    {
      const remediationName = 'RemoveUnusedSecret';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('secretsmanager:DeleteSecret', 'secretsmanager:DescribeSecret');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:secretsmanager:*:${this.account}:secret:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // SetLogGroupRetentionDays
    //
    {
      const remediationName = 'SetLogGroupRetentionDays';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('logs:PutRetentionPolicy');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(`arn:${this.partition}:logs:*:${this.account}:log-group:*`);
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // AWS-TerminateEC2Instance
    //
    {
      const remediationName = 'TerminateEC2Instance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const ec2InstanceStatusReadPerms = new PolicyStatement();
      ec2InstanceStatusReadPerms.addActions('ec2:DescribeInstanceStatus');
      ec2InstanceStatusReadPerms.effect = Effect.ALLOW;
      ec2InstanceStatusReadPerms.addResources('*');
      inlinePolicy.addStatements(ec2InstanceStatusReadPerms);

      const ec2InstanceTerminatePerms = new PolicyStatement();
      ec2InstanceTerminatePerms.addActions('ec2:TerminateInstances');
      ec2InstanceTerminatePerms.effect = Effect.ALLOW;
      ec2InstanceTerminatePerms.addResources(`arn:${this.partition}:ec2:*:${this.account}:instance/*`);
      inlinePolicy.addStatements(ec2InstanceTerminatePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableAPIGatewayCacheDataEncryption
    //
    {
      const remediationName = 'EnableAPIGatewayCacheDataEncryption';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('apigateway:PATCH', 'apigateway:GET');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources(
        `arn:${this.partition}:apigateway:*::/apis/*/stages`,
        `arn:${this.partition}:apigateway:*::/apis/*/stages/*`,
        `arn:${this.partition}:apigateway:*::/apis/*`,
        `arn:${this.partition}:apigateway:*::/apis`,
      );
      inlinePolicy.addStatements(remediationPolicy);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // ConfigureAutoScalingLaunchConfigToRequireIMDSv2
    //
    {
      const remediationName = 'ConfigureAutoScalingLaunchConfigToRequireIMDSv2';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole', 'iam:PassRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(`arn:${this.partition}:iam::${this.account}:role/AmazonSSMRoleForInstancesQuickSetup`);
      inlinePolicy.addStatements(iamPerms);

      const autoScalingResourceLevelPerms = new PolicyStatement();
      autoScalingResourceLevelPerms.addActions(
        'autoscaling:UpdateAutoScalingGroup',
        'autoscaling:CreateLaunchConfiguration',
        'autoscaling:DeleteLaunchConfiguration',
      );
      autoScalingResourceLevelPerms.effect = Effect.ALLOW;
      autoScalingResourceLevelPerms.addResources(
        `arn:${this.partition}:autoscaling:*:${this.account}:autoScalingGroup:*:autoScalingGroupName/*`,
        `arn:${this.partition}:autoscaling:*:${this.account}:launchConfiguration:*:launchConfigurationName/*`,
      );
      inlinePolicy.addStatements(autoScalingResourceLevelPerms);

      const autoScalingDescribePerms = new PolicyStatement();
      autoScalingDescribePerms.addActions(
        'autoscaling:DescribeAutoScalingGroups',
        'autoscaling:DescribeLaunchConfigurations',
      );
      autoScalingDescribePerms.effect = Effect.ALLOW;
      autoScalingDescribePerms.addResources('*');
      inlinePolicy.addStatements(autoScalingDescribePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // ConfigureAutoScalingLaunchConfigToRequireIMDSv2
    //
    {
      const remediationName = 'ConfigureAutoScalingLaunchConfigNoPublicIP';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole', 'iam:PassRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(`arn:${this.partition}:iam::${this.account}:role/AmazonSSMRoleForInstancesQuickSetup`);
      inlinePolicy.addStatements(iamPerms);

      const autoScalingResourceLevelPerms = new PolicyStatement();
      autoScalingResourceLevelPerms.addActions(
        'autoscaling:UpdateAutoScalingGroup',
        'autoscaling:CreateLaunchConfiguration',
        'autoscaling:DeleteLaunchConfiguration',
      );
      autoScalingResourceLevelPerms.effect = Effect.ALLOW;
      autoScalingResourceLevelPerms.addResources(
        `arn:${this.partition}:autoscaling:*:${this.account}:autoScalingGroup:*:autoScalingGroupName/*`,
        `arn:${this.partition}:autoscaling:*:${this.account}:launchConfiguration:*:launchConfigurationName/*`,
      );
      inlinePolicy.addStatements(autoScalingResourceLevelPerms);

      const autoScalingDescribePerms = new PolicyStatement();
      autoScalingDescribePerms.addActions(
        'autoscaling:DescribeAutoScalingGroups',
        'autoscaling:DescribeLaunchConfigurations',
      );
      autoScalingDescribePerms.effect = Effect.ALLOW;
      autoScalingDescribePerms.addResources('*');
      inlinePolicy.addStatements(autoScalingDescribePerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for to allow remediation for any resource.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableMacie
    //
    {
      const remediationName = 'EnableMacie';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermissions = new PolicyStatement();
      remediationPermissions.addActions('macie2:EnableMacie');
      remediationPermissions.effect = Effect.ALLOW;
      remediationPermissions.addResources('*');
      inlinePolicy.addStatements(remediationPermissions);

      const serviceRolePermissions = new PolicyStatement();
      serviceRolePermissions.addActions('iam:CreateServiceLinkedRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy');
      serviceRolePermissions.effect = Effect.ALLOW;
      serviceRolePermissions.addResources(
        `arn:${this.partition}:iam::${this.account}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie*`,
      );
      inlinePolicy.addStatements(serviceRolePermissions);

      // Add protection against permission mutation on own role
      const denyPermissionMutation = new PolicyStatement();
      denyPermissionMutation.addActions(...PRIVILEGE_ESCALATION_ACTIONS);
      denyPermissionMutation.effect = Effect.DENY;
      denyPermissionMutation.addResources(
        `arn:${this.partition}:iam::${
          this.account
        }:role/${remediationRoleNameBase}${remediationName}-${props.roleStack.getNamespace()}`,
      );
      inlinePolicy.addStatements(denyPermissionMutation);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource wildcard (*) is required by the EnableMacie API.',
            },
          ],
        },
      };
    }

    //-----------------------
    // EnableAPIGatewayExecutionLogs
    //
    {
      const remediationName = 'EnableAPIGatewayExecutionLogs';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const restApiPermissions = new PolicyStatement();
      restApiPermissions.addActions('apigateway:PATCH');
      restApiPermissions.effect = Effect.ALLOW;
      restApiPermissions.addResources(`arn:${this.partition}:apigateway:${this.region}::/restapis/*/stages/*`);
      inlinePolicy.addStatements(restApiPermissions);

      const websocketApiPermissions = new PolicyStatement();
      websocketApiPermissions.addActions('apigateway:PATCH', 'apigateway:GET');
      websocketApiPermissions.effect = Effect.ALLOW;
      websocketApiPermissions.addResources(`arn:${this.partition}:apigateway:${this.region}::/apis/*/stages/*`);
      inlinePolicy.addStatements(websocketApiPermissions);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource wildcard (*) is required to update any API Stage in the member account.',
            },
          ],
        },
      };
    }
    //-----------------------
    // EnableAthenaWorkGroupLogging
    //
    {
      const remediationName = 'EnableAthenaWorkGroupLogging';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const athenaPermissions = new PolicyStatement();
      athenaPermissions.addActions('athena:UpdateWorkGroup');
      athenaPermissions.effect = Effect.ALLOW;
      athenaPermissions.addResources(`arn:${this.partition}:athena:*:${this.account}:workgroup/*`);
      inlinePolicy.addStatements(athenaPermissions);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName, {
        ssmDocName: remediationName,
        ssmDocPath: ssmdocs,
        ssmDocFileName: `${remediationName}.yaml`,
        scriptPath: `${ssmdocs}/scripts`,
        solutionVersion: props.solutionVersion,
        solutionDistBucket: props.solutionDistBucket,
        solutionId: props.solutionId,
        namespace: namespace,
      });
      const childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource wildcard (*) is required to update any Athena Work Group in the member account.',
            },
          ],
        },
      };
    }
  }
}
