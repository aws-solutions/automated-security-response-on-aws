// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//
// Remediation Runbook Stack - installs non standard-specific remediation
// runbooks that are used by one or more standards
//
import * as cdk from 'aws-cdk-lib';
import {
  PolicyStatement,
  PolicyDocument,
  Effect,
  Role,
  Policy,
  ServicePrincipal,
  CfnPolicy,
  CfnRole,
} from 'aws-cdk-lib/aws-iam';
import { OrchestratorMemberRole } from './orchestrator_roles-construct';
import AdminAccountParam from './admin-account-param';
import { Rds6EnhancedMonitoringRole } from './rds6-remediation-resources';
import { RunbookFactory } from './runbook_factory';
import { SNS2DeliveryStatusLoggingRole } from './sns2-remediation-resources';
import { SsmRole } from './ssmplaybook';
import { Aspects, CfnParameter } from 'aws-cdk-lib';
import { WaitProvider } from './wait-provider';
import SsmDocRateLimit from './ssm-doc-rate-limit';

export interface MemberRoleStackProps extends cdk.StackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
}

export class MemberRoleStack extends cdk.Stack {
  _orchestratorMemberRole: OrchestratorMemberRole;

  constructor(scope: cdk.App, id: string, props: MemberRoleStackProps) {
    super(scope, id, props);
    /********************
     ** Parameters
     ********************/
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
    const adminRoleName = `${RESOURCE_PREFIX}-SHARR-Orchestrator-Admin`;

    const adminAccount = new AdminAccountParam(this, 'AdminAccountParameter');
    this._orchestratorMemberRole = new OrchestratorMemberRole(this, 'OrchestratorMemberRole', {
      solutionId: props.solutionId,
      adminAccountId: adminAccount.value,
      adminRoleName: adminRoleName,
    });
  }

  getOrchestratorMemberRole(): OrchestratorMemberRole {
    return this._orchestratorMemberRole;
  }
}

export interface StackProps extends cdk.StackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
  ssmdocs?: string;
  roleStack: MemberRoleStack;
}

export class RemediationRunbookStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: StackProps) {
    super(scope, id, props);

    const waitProviderServiceTokenParam = new CfnParameter(this, 'WaitProviderServiceToken');

    const waitProvider = WaitProvider.fromServiceToken(
      this,
      'WaitProvider',
      waitProviderServiceTokenParam.valueAsString,
    );

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
    // CreateCloudTrailMultiRegionTrail
    //
    {
      const remediationName = 'CreateCloudTrailMultiRegionTrail';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const cloudtrailPerms = new PolicyStatement();
      cloudtrailPerms.addActions('cloudtrail:CreateTrail', 'cloudtrail:UpdateTrail', 'cloudtrail:StartLogging');
      cloudtrailPerms.effect = Effect.ALLOW;
      cloudtrailPerms.addResources('*');
      inlinePolicy.addStatements(cloudtrailPerms);

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

    //----------------------------
    // EnableServerAccessLoggingS3
    //
    {
      const remediationName = 'EnableServerAccessLoggingS3';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('s3:CreateBucket', 's3:PutBucketLogging');
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
        }
      );

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
    // CreateIAMRole
    //
    {
      const remediationName = 'CreateIAMRole';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole', 'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:TagRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(`arn:${this.partition}:iam::${this.account}:role/*`);
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
        }
      );
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
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
    // CreateIAMGroupToAttachUserPolicy
    //
    {
      const remediationName = 'CreateIAMGroupToAttachUserPolicy';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetGroup', 'iam:CreateGroup', 'iam:AddUserToGroup', 'iam:AttachGroupPolicy');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(`arn:${this.partition}:iam::${this.account}:group/*`);
      inlinePolicy.addStatements(iamPerms);

      const iamPolicyPerms = new PolicyStatement();
      iamPolicyPerms.addActions('iam:CreatePolicy');
      iamPolicyPerms.effect = Effect.ALLOW;
      iamPolicyPerms.addResources(`arn:${this.partition}:iam::${this.account}:policy/*`);

      const iamUserPerms = new PolicyStatement();
      iamUserPerms.addActions('iam:GetUserPolicy');
      iamUserPerms.addActions('iam:DeleteUserPolicy');
      iamUserPerms.addActions('iam:DetachUserPolicy');
      iamUserPerms.effect = Effect.ALLOW;
      iamUserPerms.addResources(`arn:${this.partition}:iam::${this.account}:user/*`);
      inlinePolicy.addStatements(iamUserPerms);

      new SsmRole(props.roleStack, 'RemediationRole ' + remediationName, {
        solutionId: props.solutionId,
        ssmDocName: remediationName,
        remediationPolicy: inlinePolicy,
        remediationRoleName: `${remediationRoleNameBase}${remediationName}`,
      });

      RunbookFactory.createRemediationRunbook(this, 'ASR ' + remediationName,
        {
          ssmDocName: remediationName,
          ssmDocPath: ssmdocs,
          ssmDocFileName: `${remediationName}.yaml`,
          scriptPath: `${ssmdocs}/scripts`,
          solutionVersion: props.solutionVersion,
          solutionDistBucket: props.solutionDistBucket,
          solutionId: props.solutionId,
        }
      );
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
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
    // DetachIAMPolicyFromUsers
    //
    {
      const remediationName = 'DetachIAMPolicyFromUsers';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetPolicy', 'iam:ListEntitiesForPolicy');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources(`arn:${this.partition}:iam::${this.account}:policy/*`);
      inlinePolicy.addStatements(iamPerms);

      const iamUserPerms = new PolicyStatement();
      iamUserPerms.addActions('iam:DetachUserPolicy');
      iamUserPerms.effect = Effect.ALLOW;
      iamUserPerms.addResources(`arn:${this.partition}:iam::${this.account}:user/*`);
      inlinePolicy.addStatements(iamUserPerms);

      const iamGroupPerms = new PolicyStatement();
      iamGroupPerms.addActions('iam:DetachGroupPolicy');
      iamGroupPerms.effect = Effect.ALLOW;
      iamGroupPerms.addResources(`arn:${this.partition}:iam::${this.account}:group/*`);
      inlinePolicy.addStatements(iamGroupPerms);

      const iamRolePerms = new PolicyStatement();
      iamRolePerms.addActions('iam:DetachRolePolicy');
      iamRolePerms.effect = Effect.ALLOW;
      iamRolePerms.addResources(`arn:${this.partition}:iam::${this.account}:role/*`);
      inlinePolicy.addStatements(iamRolePerms);

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
        }
      );
      // CFN-NAG
      // WARN W12: IAM policy should not allow * resource

      let childToMod = inlinePolicy.node.findChild('Resource') as CfnPolicy;
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

      {
        const snsPerms = new PolicyStatement();
        snsPerms.addActions('sns:CreateTopic', 'sns:SetTopicAttributes');
        snsPerms.effect = Effect.ALLOW;
        snsPerms.addResources(`arn:${this.partition}:sns:*:${this.account}:SO0111-SHARR-LocalAlarmNotification`);
        inlinePolicy.addStatements(snsPerms);
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
      });
    }
    //-----------------------
    // EnableAutoScalingGroupELBHealthCheck
    //
    {
      const remediationName = 'EnableAutoScalingGroupELBHealthCheck';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);
      const asPerms = new PolicyStatement();
      asPerms.addActions('autoscaling:UpdateAutoScalingGroup', 'autoscaling:DescribeAutoScalingGroups');
      asPerms.effect = Effect.ALLOW;
      asPerms.addResources('*');
      inlinePolicy.addStatements(asPerms);

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
          `arn:${this.partition}:iam::${this.account}:role/SO0111-CreateAccessLoggingBucket`,
        );
        inlinePolicy.addStatements(iamPerms);
      }
      {
        const snsPerms = new PolicyStatement();
        snsPerms.addActions('sns:CreateTopic', 'sns:SetTopicAttributes');
        snsPerms.effect = Effect.ALLOW;
        snsPerms.addResources(`arn:${this.partition}:sns:*:${this.account}:SO0111-SHARR-AWSConfigNotification`);
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
        roleName: `${RESOURCE_PREFIX}-CloudTrailToCloudWatchLogs`,
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
        ctperms.addActions('cloudtrail:UpdateTrail');

        ctperms.effect = Effect.ALLOW;
        ctperms.addResources('arn:' + this.partition + ':cloudtrail:*:' + this.account + ':trail/*');
        inlinePolicy.addStatements(ctperms);
      }
      {
        const ctcwiam = new PolicyStatement();
        ctcwiam.addActions('iam:PassRole');
        ctcwiam.addResources(ctcw_remediation_role.roleArn);
        inlinePolicy.addStatements(ctcwiam);
      }
      {
        const ctcwlogs = new PolicyStatement();
        ctcwlogs.addActions('logs:CreateLogGroup', 'logs:DescribeLogGroups');
        ctcwlogs.effect = Effect.ALLOW;
        ctcwlogs.addResources('*');
        inlinePolicy.addStatements(ctcwlogs);
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
      cloudtrailPerms.addResources('*');
      inlinePolicy.addStatements(cloudtrailPerms);

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
          `arn:${this.partition}:iam::${this.account}:role/${RESOURCE_PREFIX}-${remediationName}-remediationRole`,
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
        const validationPerms = new PolicyStatement();
        validationPerms.addActions('ec2:DescribeFlowLogs', 'logs:CreateLogGroup', 'logs:DescribeLogGroups');
        validationPerms.effect = Effect.ALLOW;
        validationPerms.addResources('*');
        inlinePolicy.addStatements(validationPerms);
      }

      // Remediation Role - used in the remediation
      const remediation_policy = new PolicyStatement();
      remediation_policy.effect = Effect.ALLOW;
      remediation_policy.addActions(
        'logs:CreateLogGroup',
        'logs:CreateLogStream',
        'logs:DescribeLogGroups',
        'logs:DescribeLogStreams',
        'logs:PutLogEvents',
      );
      remediation_policy.addResources('*');

      const remediation_doc = new PolicyDocument();
      remediation_doc.addStatements(remediation_policy);

      const remediation_role = new Role(props.roleStack, 'EnableVPCFlowLogs-remediationrole', {
        assumedBy: new ServicePrincipal('vpc-flow-logs.amazonaws.com'),
        inlinePolicies: {
          default_lambdaPolicy: remediation_doc,
        },
        roleName: `${RESOURCE_PREFIX}-EnableVPCFlowLogs-remediationRole`,
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
      );
      s3Perms.effect = Effect.ALLOW;
      s3Perms.addResources('*');

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
      const ec2Perms = new PolicyStatement();
      ec2Perms.addActions('ec2:ModifySnapshotAttribute', 'ec2:DescribeSnapshots');
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
      remediationPerms.addResources('*');
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
      lambdaPerms.addResources('*');
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
        remediationPerms.addResources('*');
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
      remediationPolicy.addResources('*');
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
        `arn:${this.partition}:iam::${this.account}:role/${remediationRoleNameBase}${remediationName}`,
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
      );
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('redshift:ModifyCluster', 'redshift:DescribeClusters');
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
      remediationPolicy.addResources('*');
      inlinePolicy.addStatements(remediationPolicy);
      remediationPolicy.addActions('s3:PutObject');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('redshift:ModifyCluster', 'redshift:DescribeClusters');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('redshift:ModifyCluster', 'redshift:DescribeClusters');
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
        `arn:${this.partition}:iam::${this.account}:role/${remediationRoleNameBase}${remediationName}`,
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
      cfnPerms.addResources('*');
      inlinePolicy.addStatements(cfnPerms);

      const snsPerms = new PolicyStatement();
      snsPerms.addActions('sns:CreateTopic', 'sns:Publish');
      snsPerms.effect = Effect.ALLOW;
      snsPerms.addResources(
        `arn:${this.partition}:sns:${this.region}:${this.account}:SO0111-ASR-CloudFormationNotifications`,
      );
      inlinePolicy.addStatements(snsPerms);

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('servicecatalog:GetApplication', 'iam:GetRole');
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
      s3Perms.addActions('s3:PutBucketLogging', 's3:CreateBucket', 's3:PutEncryptionConfiguration');
      s3Perms.addActions('s3:PutBucketAcl');
      s3Perms.effect = Effect.ALLOW;
      s3Perms.addResources('*');

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

      const remediationPermsEc2 = new PolicyStatement();
      remediationPermsEc2.addActions(
        'ec2:DescribeSecurityGroupReferences',
        'ec2:DescribeSecurityGroups',
        'ec2:UpdateSecurityGroupRuleDescriptionsEgress',
        'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
        'ec2:RevokeSecurityGroupIngress',
        'ec2:RevokeSecurityGroupEgress',
      );
      remediationPermsEc2.effect = Effect.ALLOW;
      remediationPermsEc2.addResources('*');
      inlinePolicy.addStatements(remediationPermsEc2);

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
    // AWSConfigRemediation-EnableCloudFrontAccessLogs
    //
    {
      const remediationName = 'EnableCloudFrontAccessLogsDocument';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsAPIGateway = new PolicyStatement();
      remediationPermsAPIGateway.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'cloudfront:GetDistribution',
        'cloudfront:GetDistributionConfig',
        'cloudfront:UpdateDistribution',
        's3:GetBucketLocation',
        's3:GetBucketAcl',
        's3:PutBucketAcl'
      );
      remediationPermsAPIGateway.effect = Effect.ALLOW;
      remediationPermsAPIGateway.addResources('*');
      inlinePolicy.addStatements(remediationPermsAPIGateway);

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
    // AWS-EnableDocDbClusterBackupRetentionPeriod
    //
    {
      const remediationName = 'EnableDocDbClusterBackupRetentionPeriod';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsDocumentDb = new PolicyStatement();
      remediationPermsDocumentDb.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'docdb:DescribeDBClusters',
        'docdb:ModifyDBCluster',
        'rds:DescribeDBClusters',
        'rds:ModifyDBCluster'
      );
      remediationPermsDocumentDb.effect = Effect.ALLOW;
      remediationPermsDocumentDb.addResources('*');
      inlinePolicy.addStatements(remediationPermsDocumentDb);

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
    // AWSConfigRemediation-EnableAPIGatewayTracing
    //
    {
      const remediationName = 'EnableAPIGatewayTracing';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsAPIGateway = new PolicyStatement();
      remediationPermsAPIGateway.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'config:GetResourceConfigHistory',
        'apigateway:UpdateStage',
        'apigateway:GetStage',
      );
      remediationPermsAPIGateway.effect = Effect.ALLOW;
      remediationPermsAPIGateway.addResources('*');
      inlinePolicy.addStatements(remediationPermsAPIGateway);

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
    // AWSConfigRemediation-EnableCloudFrontOriginAccessIdentity
    //
    {
      const remediationName = 'EnableCloudFrontOriginAccessIdentity';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsCloudFront = new PolicyStatement();
      remediationPermsCloudFront.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'cloudfront:GetDistributionConfig',
        'cloudfront:UpdateDistribution',
      );
      remediationPermsCloudFront.effect = Effect.ALLOW;
      remediationPermsCloudFront.addResources('*');
      inlinePolicy.addStatements(remediationPermsCloudFront);

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
    // AWSConfigRemediation-EnablePITRForDynamoDbTable
    //
    {
      const remediationName = 'EnablePITRForDynamoDbTable';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsDynamoDB = new PolicyStatement();
      remediationPermsDynamoDB.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'dynamodb:DescribeContinuousBackups',
        'dynamodb:UpdateContinuousBackups',
      );
      remediationPermsDynamoDB.effect = Effect.ALLOW;
      remediationPermsDynamoDB.addResources('*');
      inlinePolicy.addStatements(remediationPermsDynamoDB);

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
    // AWS-EnableDynamoDbAutoscaling
    //
    {
      const remediationName = 'EnableDynamoDbAutoscalingDocument';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsDynamoDB = new PolicyStatement();
      remediationPermsDynamoDB.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'application-autoscaling:DescribeScalableTargets',
        'application-autoscaling:DescribeScalingPolicies',
        'application-autoscaling:PutScalingPolicy',
        'application-autoscaling:RegisterScalableTarget',
      );
      remediationPermsDynamoDB.effect = Effect.ALLOW;
      remediationPermsDynamoDB.addResources('*');
      inlinePolicy.addStatements(remediationPermsDynamoDB);

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
    // AWSSupport-CollectEKSInstanceLogs
    //
    {
      const remediationName = 'CollectEKSInstanceLogs';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsEKS = new PolicyStatement();
      remediationPermsEKS.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'ssm:SendCommand',
        's3:PutObject' //?
      );
      remediationPermsEKS.effect = Effect.ALLOW;
      remediationPermsEKS.addResources('*');
      inlinePolicy.addStatements(remediationPermsEKS);

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
    // AWSConfigRemediation-DropInvalidHeadersForALB
    //
    {
      const remediationName = 'DropInvalidHeadersForALB';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsELB = new PolicyStatement();
      remediationPermsELB.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'elasticloadbalancing:DescribeLoadBalancerAttributes',
        'elasticloadbalancing:ModifyLoadBalancerAttributes'
      );
      remediationPermsELB.effect = Effect.ALLOW;
      remediationPermsELB.addResources('*');
      inlinePolicy.addStatements(remediationPermsELB);

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
    // AWSConfigRemediation-EnableELBDeletionProtection
    //
    {
      const remediationName = 'EnableELBDeletionProtection';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsELB = new PolicyStatement();
      remediationPermsELB.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'elasticloadbalancing:DescribeLoadBalancerAttributes',
        'elasticloadbalancing:DescribeLoadBalancers',
        'elasticloadbalancing:ModifyLoadBalancerAttributes'
      );
      remediationPermsELB.effect = Effect.ALLOW;
      remediationPermsELB.addResources('*');
      inlinePolicy.addStatements(remediationPermsELB);

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
    // AWS-EnableNeptuneDbAuditLogsToCloudWatch
    //
    {
      const remediationName = 'EnableNeptuneDbAuditLogsToCloudWatch';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsNeptune = new PolicyStatement();
      remediationPermsNeptune.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'neptune:DescribeDBCluster',
        'neptune:ModifyDBCluster',
        'rds:DescribeDBClusters',
        'rds:ModifyDBCluster'
      );
      remediationPermsNeptune.effect = Effect.ALLOW;
      remediationPermsNeptune.addResources('*');
      inlinePolicy.addStatements(remediationPermsNeptune);

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
    // AWS-EnableNeptuneDbBackupRetentionPeriod
    //
    {
      const remediationName = 'EnableNeptuneDbBackupRetentionPeriod';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsNeptune = new PolicyStatement();
      remediationPermsNeptune.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'neptune:DescribeDBCluster',
        'neptune:ModifyDBCluster',
        'rds:DescribeDBClusters',
        'rds:ModifyDBCluster'
      );
      remediationPermsNeptune.effect = Effect.ALLOW;
      remediationPermsNeptune.addResources('*');
      inlinePolicy.addStatements(remediationPermsNeptune);

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
    // AWS-EnableNeptuneDbClusterDeletionProtection
    //
    {
      const remediationName = 'EnableNeptuneDbClusterDeletionProtection';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsNeptune = new PolicyStatement();
      remediationPermsNeptune.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'neptune:DescribeDBCluster',
        'neptune:ModifyDBCluster',
        'rds:DescribeDBClusters',
        'rds:ModifyDBCluster'
      );
      remediationPermsNeptune.effect = Effect.ALLOW;
      remediationPermsNeptune.addResources('*');
      inlinePolicy.addStatements(remediationPermsNeptune);

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
    // AWSConfigRemediation-EnableRDSInstanceBackup
    //
    {
      const remediationName = 'EnableRDSInstanceBackup';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsRDS = new PolicyStatement();
      remediationPermsRDS.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'rds:DescribeDBInstances',
        'rds:ModifyDBInstance',
      );
      remediationPermsRDS.effect = Effect.ALLOW;
      remediationPermsRDS.addResources('*');
      inlinePolicy.addStatements(remediationPermsRDS);

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
    // AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSDBInstance
    //
    {
      const remediationName = 'EnableCopyTagsToSnapshotOnRDSDBInstance';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsRDS = new PolicyStatement();
      remediationPermsRDS.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'config:GetResourceConfigHistory',
        'rds:DescribeDBInstances',
        'rds:ModifyDBInstance',
      );
      remediationPermsRDS.effect = Effect.ALLOW;
      remediationPermsRDS.addResources('*');
      inlinePolicy.addStatements(remediationPermsRDS);

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
    // AWS-ConfigureS3BucketVersioning
    //
    {
      const remediationName = 'ConfigureS3BucketVersioning';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsS3 = new PolicyStatement();
      remediationPermsS3.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        's3:PutBucketVersioning',
        's3:GetBucketVersioning',
      );
      remediationPermsS3.effect = Effect.ALLOW;
      remediationPermsS3.addResources('*');
      inlinePolicy.addStatements(remediationPermsS3);

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
    // AWS-EnableStepFunctionsStateMachineLogging
    //
    {
      const remediationName = 'EnableStepFunctionsStateMachineLogging';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsStepFn = new PolicyStatement();
      remediationPermsStepFn.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'states:DescribeStateMachine',
        'states:UpdateStateMachine',
      );
      remediationPermsStepFn.effect = Effect.ALLOW;
      remediationPermsStepFn.addResources('*');
      inlinePolicy.addStatements(remediationPermsStepFn);

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
    // AWSConfigRemediation-EnableWAFV2Logging
    //
    {
      const remediationName = 'EnableWAFV2LoggingDocument';
      const inlinePolicy = new Policy(props.roleStack, `ASR-Remediation-Policy-${remediationName}`);

      const remediationPermsWAF = new PolicyStatement();
      remediationPermsWAF.addActions(
        'ssm:GetAutomationExecution',
        'ssm:StartAutomationExecution',
        'firehose:DescribeDeliveryStream',
        'wafv2:PutLoggingConfiguration',
        'wafv2:GetLoggingConfiguration'
      );
      remediationPermsWAF.effect = Effect.ALLOW;
      remediationPermsWAF.addResources('*');
      inlinePolicy.addStatements(remediationPermsWAF);

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
          `arn:${this.partition}:iam::${this.account}:role/${RESOURCE_PREFIX}-RDSMonitoring-remediationRole`,
        );
        inlinePolicy.addStatements(iamPerms);
      }
      {
        const rdsPerms = new PolicyStatement();
        rdsPerms.addActions('rds:DescribeDBInstances', 'rds:ModifyDBInstance');
        rdsPerms.effect = Effect.ALLOW;
        rdsPerms.addResources('*');
        inlinePolicy.addStatements(rdsPerms);
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
        roleName: `${RESOURCE_PREFIX}-RDSMonitoring-remediationRole`,
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
      remediationPerms.addResources('*');
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

      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources('arn:' + this.partition + ':iam::' + this.account + ':role/RDSEnhancedMonitoringRole');
      inlinePolicy.addStatements(iamPerms);

      const configPerms = new PolicyStatement();
      configPerms.addActions('config:GetResourceConfigHistory');
      configPerms.effect = Effect.ALLOW;
      configPerms.addResources('*');
      inlinePolicy.addStatements(configPerms);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBClusters', 'rds:ModifyDBCluster', 'rds:ModifyDBInstance');
      rdsPerms.effect = Effect.ALLOW;
      rdsPerms.addResources('*');
      inlinePolicy.addStatements(rdsPerms);

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

      const iamPerms = new PolicyStatement();
      iamPerms.addActions('iam:GetRole');
      iamPerms.effect = Effect.ALLOW;
      iamPerms.addResources('arn:' + this.partition + ':iam::' + this.account + ':role/RDSEnhancedMonitoringRole');
      inlinePolicy.addStatements(iamPerms);

      const configPerms = new PolicyStatement();
      configPerms.addActions('config:GetResourceConfigHistory');
      configPerms.effect = Effect.ALLOW;
      configPerms.addResources('*');
      inlinePolicy.addStatements(configPerms);

      const rdsPerms = new PolicyStatement();
      rdsPerms.addActions('rds:DescribeDBClusters', 'rds:ModifyDBCluster');
      rdsPerms.effect = Effect.ALLOW;
      rdsPerms.addResources('*');
      inlinePolicy.addStatements(rdsPerms);

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
      rdsPerms.addResources('*');
      inlinePolicy.addStatements(rdsPerms);

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
      rdsPerms.addResources('*');
      inlinePolicy.addStatements(rdsPerms);

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

      const remediationPolicy1 = new PolicyStatement();
      remediationPolicy1.addActions(
        'ec2:UpdateSecurityGroupRuleDescriptionsEgress',
        'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
        'ec2:RevokeSecurityGroupIngress',
        'ec2:RevokeSecurityGroupEgress',
      );
      remediationPolicy1.effect = Effect.ALLOW;
      remediationPolicy1.addResources('arn:' + this.partition + ':ec2:*:' + this.account + ':security-group/*');

      const remediationPolicy2 = new PolicyStatement();
      remediationPolicy2.addActions('ec2:DescribeSecurityGroupReferences', 'ec2:DescribeSecurityGroups');
      remediationPolicy2.effect = Effect.ALLOW;
      remediationPolicy2.addResources('*');

      inlinePolicy.addStatements(remediationPolicy1, remediationPolicy2);

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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'iam:UpdateAccountPasswordPolicy',
        'iam:GetAccountPasswordPolicy',
        'ec2:UpdateSecurityGroupRuleDescriptionsIngress',
        'ec2:RevokeSecurityGroupIngress',
        'ec2:RevokeSecurityGroupEgress',
      );
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('rds:DescribeDBInstances', 'rds:ModifyDBInstance');
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
      remediationPolicy.addResources('*');
      inlinePolicy.addStatements(remediationPolicy);

      const sns2Role = new SNS2DeliveryStatusLoggingRole(props.roleStack, 'SNS2DeliveryStatusLoggingRole', {
        roleName: `${RESOURCE_PREFIX}-SNS2DeliveryStatusLogging-remediationRole`,
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ec2:DescribeSubnets', 'ec2:ModifySubnetAttribute');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ec2:DescribeInstances', 'ec2:ModifyInstanceMetadataOptions');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ec2:DescribeSecurityGroupRules', 'ec2:RevokeSecurityGroupIngress');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ec2:ModifyTransitGateway', 'ec2:DescribeTransitGateways');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions(
        'guardduty:ListDetectors',
        'guardduty:CreateDetector',
        'guardduty:GetDetector',
        'guardduty:UpdateDetector',
      );
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ec2:DescribeSecurityGroupRules', 'ec2:RevokeSecurityGroupIngress');
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

      const remediationPolicy = new PolicyStatement();
      remediationPolicy.addActions('ec2:TerminateInstances', 'ec2:DescribeInstanceStatus');
      remediationPolicy.effect = Effect.ALLOW;
      remediationPolicy.addResources('*');
      inlinePolicy.addStatements(remediationPolicy);

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
  }
}