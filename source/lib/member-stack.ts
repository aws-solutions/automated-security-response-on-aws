// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { App, CfnResource, Stack, StackProps } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import AdminAccountParam from './parameters/admin-account-param';
import { RedshiftAuditLogging } from './member/redshift-audit-logging';
import { MemberRemediationKey } from './member/remediation-key';
import { MemberLogGroup } from './member/log-group';
import { MemberBucketEncryption } from './member/bucket-encryption';
import { RemediationConfigurationBucket } from './member/remediation-configuration-bucket';
import { MemberVersion } from './member/version';
import { SerializedNestedStackFactory } from './cdk-helper/nested-stack';
import { WaitProvider } from './wait-provider';
import { MemberPlaybook } from './member-playbook';
import { scPlaybookProps, standardPlaybookProps } from '../playbooks/playbook-index';
import NamespaceParam from './parameters/namespace-param';
import MetricResources from './cdk-helper/metric-resources';
import { PlaybookSelectionValidator } from './cdk-helper/playbook-selection-validator';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { getMemberStackLimit } from './config/cdk-config';
import { runbookStackCount, runbookStackSuffix } from './remediation-runbooks';

export interface SolutionProps extends StackProps {
  solutionId: string;
  resourceNamePrefix: string;
  solutionDistBucket: string;
  solutionTradeMarkName: string;
  solutionVersion: string;
  runtimePython: Runtime;
  SNSTopicName: string;
  cloudTrailLogGroupName: string;
}

export class MemberStack extends Stack {
  constructor(scope: App, id: string, props: SolutionProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);

    const adminAccountParam = new AdminAccountParam(this, 'AdminAccountParameter');

    const namespaceParam = new NamespaceParam(this, 'Namespace');

    const enableCloudTrailParam = new cdk.CfnParameter(this, 'EnableCloudTrailForASRActionLog', {
      type: 'String',
      default: 'no',
      allowedValues: ['yes', 'no'],
      description: 'Create a CloudTrail to monitor ASR actions in this account on the ASR CloudWatch Dashboard. ',
    });
    const cloudTrailCondition = new cdk.CfnCondition(this, 'CloudTrailCondition', {
      expression: cdk.Fn.conditionEquals(enableCloudTrailParam, 'yes'),
    });

    const redShiftLogging = new RedshiftAuditLogging(this, 'RedshiftAuditLogging', {
      resourceNamePrefix: props.resourceNamePrefix,
    });

    const remediationKey = new MemberRemediationKey(this, 'MemberKey', {
      resourceNamePrefix: props.resourceNamePrefix,
    });

    new MemberVersion(this, 'MemberVersion', {
      resourceNamePrefix: props.resourceNamePrefix,
      solutionVersion: props.solutionVersion,
    });

    const memberLogGroup = new MemberLogGroup(this, 'MemberLogGroup', {
      resourceNamePrefix: props.resourceNamePrefix,
    });

    new MemberBucketEncryption(this, 'MemberBucketEncryption', {
      resourceNamePrefix: props.resourceNamePrefix,
    });

    new RemediationConfigurationBucket(this, 'RemediationConfigBucket', {
      resourceNamePrefix: props.resourceNamePrefix,
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTradeMarkName,
      solutionDistBucket: props.solutionDistBucket,
      runtimePython: props.runtimePython,
      kmsKey: remediationKey.key,
    });

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

    // Reference one runbook nested stack per document chunk. Count and per-index naming come from the
    // shared helpers in remediation-runbooks.ts so this referencing loop and the synthesizing loop in
    // solution_deploy.ts stay in lock-step: every stack this file references matches a template that
    // file emits.
    const numRunbookStacks = runbookStackCount(getMemberStackLimit('runbook'));
    const runbookNestedStacks: Stack[] = [];
    for (let runbookStackIndex = 0; runbookStackIndex < numRunbookStacks; runbookStackIndex++) {
      const runbookStackSuffixValue = runbookStackSuffix(runbookStackIndex);
      const runbookStackId = `RunbookStackNoRoles${runbookStackSuffixValue}`;
      const templateRelativePath = `automated-security-response-remediation-runbooks${runbookStackSuffixValue}.template`;
      const nestedStackNoRoles = nestedStackFactory.addNestedStack(runbookStackId, {
        templateRelativePath,
        parameters: {
          WaitProviderServiceToken: waitProvider.serviceToken,
          Namespace: namespaceParam.value,
        },
      });
      const noRolesCfnResource = nestedStackNoRoles.nestedStackResource as CfnResource;
      noRolesCfnResource.overrideLogicalId(runbookStackId);
      runbookNestedStacks.push(nestedStackNoRoles);
    }

    const standardPlaybooks = standardPlaybookProps.map(
      (playbookProps) =>
        new MemberPlaybook(this, {
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
        }),
    );
    const securityStandardPlaybookNames = standardPlaybooks.map((playbook) => playbook.parameterName);

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

    const sortedPlaybookNames = [...securityStandardPlaybookNames].sort((a, b) => a.localeCompare(b));

    const logWriterRoleArn = `arn:${stack.partition}:iam::${adminAccountParam.value}:role/CrossAccountLogWriterRole`;

    new cdk.CfnMapping(this, 'SourceCode', {
      mapping: {
        General: {
          S3Bucket: props.solutionDistBucket,
          KeyPrefix: props.solutionTradeMarkName + '/' + props.solutionVersion,
        },
      },
    });

    const memberCloudTrailNestedStack = nestedStackFactory.addNestedStack('MemberCloudTrailStack', {
      templateRelativePath: 'automated-security-response-member-cloudtrail.template',
      parameters: {
        CloudTrailLogGroupName: props.cloudTrailLogGroupName,
        Namespace: namespaceParam.value,
        LogWriterRoleArn: logWriterRoleArn,
      },
      condition: cloudTrailCondition,
    });
    const cfnMemberCloudTrailNestedStack = memberCloudTrailNestedStack.nestedStackResource as CfnResource;
    cfnMemberCloudTrailNestedStack.overrideLogicalId(
      'MemberCloudTrailNestedStackMemberCloudTrailNestedStackResource2ED3A9F6',
    );

    const solutionsBucket = Bucket.fromBucketName(
      this,
      'SolutionsBucket',
      `${props.solutionDistBucket}-${this.region}`,
    );

    const asrLambdaLayer = new lambda.LayerVersion(this, 'ASRLambdaLayer', {
      compatibleRuntimes: [props.runtimePython],
      description: 'SO0111 ASR Common functions used by the solution',
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      code: getLambdaCode(solutionsBucket, props.solutionTradeMarkName, props.solutionVersion, 'layer.zip'),
    });

    new MetricResources(this, 'MetricResources', {
      solutionTMN: props.solutionTradeMarkName,
      solutionVersion: props.solutionVersion,
      solutionId: props.solutionId,
      runtimePython: props.runtimePython,
      solutionsBucket: solutionsBucket,
      lambdaLayer: asrLambdaLayer,
    });

    const playbookSelectionValidator = new PlaybookSelectionValidator(this, 'PlaybookSelectionValidator', {
      solutionTradeMarkName: props.solutionTradeMarkName,
      solutionVersion: props.solutionVersion,
      runtimePython: props.runtimePython,
      solutionsBucket,
      securityControlPlaybookParameter: scPlaybook.stackOption,
      standardPlaybookParameters: standardPlaybooks.map((playbook) => playbook.stackOption),
      isSecurityHubRequired: false,
    });
    [...standardPlaybooks, scPlaybook]
      .flatMap((playbook) => [playbook.playbookPrimaryStack, ...playbook.playbookOverflowStacks])
      .forEach((playbookStack) => playbookSelectionValidator.addDependent(playbookStack));
    runbookNestedStacks.forEach((runbookStack) => playbookSelectionValidator.addDependent(runbookStack));
    playbookSelectionValidator.addDependent(memberCloudTrailNestedStack);

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
}
