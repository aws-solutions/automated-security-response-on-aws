// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { StackProps, Stack, App, CfnResource } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import AdminAccountParam from './admin-account-param';
import { RedshiftAuditLogging } from './member/redshift-audit-logging';
import { MemberRemediationKey } from './member/remediation-key';
import { MemberLogGroup } from './member/log-group';
import { MemberBucketEncryption } from './member/bucket-encryption';
import { MemberVersion } from './member/version';
import { SerializedNestedStackFactory } from './cdk-helper/nested-stack';
import { WaitProvider } from './wait-provider';
import { MemberPlaybook } from './member-playbook';
import { standardPlaybookProps, scPlaybookProps } from '../playbooks/playbook-index';

export interface SolutionProps extends StackProps {
  solutionId: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionVersion: string;
  runtimePython: Runtime;
}

export class MemberStack extends Stack {
  nestedStacksWithAppRegistry: Stack[] = [];
  constructor(scope: App, id: string, props: SolutionProps) {
    super(scope, id, props);

    const adminAccountParam = new AdminAccountParam(this, 'AdminAccountParameter');

    const redShiftLogging = new RedshiftAuditLogging(this, 'RedshiftAuditLogging', { solutionId: props.solutionId });

    new MemberRemediationKey(this, 'MemberKey', { solutionId: props.solutionId });

    new MemberVersion(this, 'MemberVersion', { solutionId: props.solutionId, solutionVersion: props.solutionVersion });

    const memberLogGroup = new MemberLogGroup(this, 'MemberLogGroup', { solutionId: props.solutionId });

    new MemberBucketEncryption(this, 'MemberBucketEncryption', { solutionId: props.solutionId });

    const nestedStackFactory = new SerializedNestedStackFactory(this, 'NestedStackFactory', {
      solutionDistBucket: props.solutionDistBucket,
      solutionTMN: props.solutionTMN,
      solutionVersion: props.solutionVersion,
    });

    const waitProvider = WaitProvider.fromLambdaProps(this, 'WaitProvider', {
      solutionVersion: props.solutionVersion,
      solutionTMN: props.solutionTMN,
      solutionDistBucket: props.solutionDistBucket,
      runtimePython: props.runtimePython,
    });

    const nestedStackNoRoles = nestedStackFactory.addNestedStack('RunbookStackNoRoles', {
      templateRelativePath: 'aws-sharr-remediations.template',
      parameters: { WaitProviderServiceToken: waitProvider.serviceToken },
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
        parameters: {
          SecHubAdminAccount: adminAccountParam.value,
          WaitProviderServiceToken: waitProvider.serviceToken,
        },
      });

      securityStandardPlaybookNames.push(playbook.parameterName);

      if (playbookProps.useAppRegistry) {
        this.nestedStacksWithAppRegistry.push(playbook.playbookStack);
      }
    });

    const scPlaybook = new MemberPlaybook(this, {
      name: scPlaybookProps.name,
      defaultState: scPlaybookProps.defaultParameterValue,
      description: scPlaybookProps.description,
      nestedStackFactory,
      parameters: {
        SecHubAdminAccount: adminAccountParam.value,
        WaitProviderServiceToken: waitProvider.serviceToken,
      },
    });

    const sortedPlaybookNames = [...securityStandardPlaybookNames].sort();

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
            Parameters: [redShiftLogging.paramId, adminAccountParam.paramId],
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
