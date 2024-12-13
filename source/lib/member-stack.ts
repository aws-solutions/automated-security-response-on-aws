// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { App, CfnResource, Fn, Stack, StackProps } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import AdminAccountParam from './parameters/admin-account-param';
import { RedshiftAuditLogging } from './member/redshift-audit-logging';
import { MemberRemediationKey } from './member/remediation-key';
import { MemberLogGroup } from './member/log-group';
import { MemberBucketEncryption } from './member/bucket-encryption';
import { MemberVersion } from './member/version';
import { SerializedNestedStackFactory } from './cdk-helper/nested-stack';
import { WaitProvider } from './wait-provider';
import { MemberPlaybook } from './member-playbook';
import { scPlaybookProps, standardPlaybookProps } from '../playbooks/playbook-index';
import NamespaceParam from './parameters/namespace-param';
import { MemberCloudTrail } from './member/cloud-trail';

export interface SolutionProps extends StackProps {
  solutionId: string;
  solutionDistBucket: string;
  solutionTradeMarkName: string;
  solutionVersion: string;
  runtimePython: Runtime;
  SNSTopicName: string;
  cloudTrailLogGroupName: string;
}

export class MemberStack extends Stack {
  private readonly primarySolutionSNSTopicARN: string;
  readonly nestedStacksWithAppRegistry: Stack[] = [];

  constructor(scope: App, id: string, props: SolutionProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);

    const adminAccountParam = new AdminAccountParam(this, 'AdminAccountParameter');

    const namespaceParam = new NamespaceParam(this, 'Namespace');

    const enableCloudTrailParam = new cdk.CfnParameter(this, 'EnableCloudTrailForASRActionLog', {
      type: 'String',
      default: 'no',
      allowedValues: ['yes', 'no'],
      description: 'Create a CloudTrail to monitor ASR actions in this account on the ASR CloudWatch Dashboard?',
    });
    const cloudTrailCondition = new cdk.CfnCondition(this, 'CloudTrailCondition', {
      expression: cdk.Fn.conditionEquals(enableCloudTrailParam, 'yes'),
    });

    const redShiftLogging = new RedshiftAuditLogging(this, 'RedshiftAuditLogging', { solutionId: props.solutionId });

    new MemberRemediationKey(this, 'MemberKey', { solutionId: props.solutionId });

    new MemberVersion(this, 'MemberVersion', { solutionId: props.solutionId, solutionVersion: props.solutionVersion });

    const memberLogGroup = new MemberLogGroup(this, 'MemberLogGroup', { solutionId: props.solutionId });

    new MemberBucketEncryption(this, 'MemberBucketEncryption', { solutionId: props.solutionId });

    this.primarySolutionSNSTopicARN = `arn:${stack.partition}:sns:${stack.region}:${adminAccountParam.value}:${props.SNSTopicName}`;

    const nestedStackFactory = new SerializedNestedStackFactory(this, 'NestedStackFactory', {
      solutionDistBucket: props.solutionDistBucket,
      solutionTMN: props.solutionTradeMarkName,
      solutionVersion: props.solutionVersion,
    });

    const waitProvider = WaitProvider.fromLambdaProps(this, 'WaitProvider', {
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTradeMarkName,
      solutionDistBucket: props.solutionDistBucket,
      runtimePython: props.runtimePython,
    });

    const nestedStackNoRoles = nestedStackFactory.addNestedStack('RunbookStackNoRoles', {
      templateRelativePath: 'aws-sharr-remediations.template',
      parameters: {
        WaitProviderServiceToken: waitProvider.serviceToken,
        Namespace: namespaceParam.value,
      },
    });
    const noRolesCfnResource = nestedStackNoRoles.nestedStackResource as CfnResource;
    noRolesCfnResource.overrideLogicalId('RunbookStackNoRoles');

    this.nestedStacksWithAppRegistry.push(nestedStackNoRoles as Stack);

    const securityStandardPlaybookNames: string[] = [];
    standardPlaybookProps.forEach((playbookProps) => {
      const playbook = new MemberPlaybook(this, {
        name: playbookProps.name,
        defaultState: playbookProps.defaultParameterValue,
        description: playbookProps.description,
        nestedStackFactory,
        stackLimit: playbookProps.memberStackLimit,
        totalControls: playbookProps.totalControls,
        parameters: {
          SecHubAdminAccount: adminAccountParam.value,
          WaitProviderServiceToken: waitProvider.serviceToken,
          Namespace: namespaceParam.value,
        },
      });

      securityStandardPlaybookNames.push(playbook.parameterName);
      if (playbookProps.useAppRegistry) {
        // Intentional: not adding AppReg to playbook overflow stacks to prevent logical ID shifts which break update path.
        this.nestedStacksWithAppRegistry.push(playbook.playbookPrimaryStack);
      }
    });

    const scPlaybook = new MemberPlaybook(this, {
      name: scPlaybookProps.name,
      defaultState: scPlaybookProps.defaultParameterValue,
      description: scPlaybookProps.description,
      nestedStackFactory,
      stackLimit: scPlaybookProps.memberStackLimit,
      totalControls: scPlaybookProps.totalControls,
      parameters: {
        SecHubAdminAccount: adminAccountParam.value,
        WaitProviderServiceToken: waitProvider.serviceToken,
        Namespace: namespaceParam.value,
      },
    });

    const sortedPlaybookNames = [...securityStandardPlaybookNames].sort();

    const logWriterRoleArn = `arn:${stack.partition}:iam::${adminAccountParam.value}:role/CrossAccountLogWriterRole`;

    new cdk.CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionTradeMarkName + '/' + props.solutionVersion,
        },
      },
    });

    const memberCloudTrailNestedStack = new MemberCloudTrail(this, 'MemberCloudTrail', {
      secHubAdminAccount: adminAccountParam.value,
      region: this.region,
      solutionId: props.solutionId,
      solutionName: props.solutionTradeMarkName,
      cloudTrailLogGroupName: props.cloudTrailLogGroupName,
      namespace: namespaceParam.value,
      logWriterRoleArn,
    }).nestedStackResource as cdk.CfnResource;
    memberCloudTrailNestedStack.cfnOptions.condition = cloudTrailCondition;
    memberCloudTrailNestedStack.addPropertyOverride(
      'TemplateURL',
      `https://${Fn.findInMap('SourceCode', 'General', 'S3Bucket')}-reference.s3.amazonaws.com/${Fn.findInMap(
        'SourceCode',
        'General',
        'KeyPrefix',
      )}/aws-sharr-member-cloudtrail.template`,
    );

    /********************
     ** Metadata
     ********************/
    Stack.of(this).templateOptions.metadata = {
      'AWS::CloudFormation::Interface': {
        ParameterGroups: [
          {
            Label: { default: 'LogGroup Configuration' },
            Parameters: [memberLogGroup.paramId],
          },
          {
            Label: { default: 'Consolidated control finding Playbook' },
            Parameters: [scPlaybook.parameterName],
          },
          {
            Label: { default: 'Security Standard Playbooks' },
            Parameters: sortedPlaybookNames,
          },
          {
            Label: { default: 'Configuration' },
            Parameters: [redShiftLogging.paramId, adminAccountParam.paramId, namespaceParam.paramId],
          },
        ],
        ParameterLabels: {
          [memberLogGroup.paramId]: {
            default: 'Provide the name of the LogGroup to be used to create Metric Filters and Alarms',
          },
        },
      },
    };
  }

  getPrimarySolutionSNSTopicARN(): string {
    return this.primarySolutionSNSTopicARN;
  }
}
