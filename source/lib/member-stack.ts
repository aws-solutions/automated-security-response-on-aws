// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { readdirSync } from 'fs';
import { StackProps, Stack, App, CfnParameter, CfnCondition, Fn, CfnResource } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import AdminAccountParam from './admin-account-param';
import { RedshiftAuditLogging } from './member/redshift-audit-logging';
import { MemberRemediationKey } from './member/remediation-key';
import { MemberLogGroup } from './member/log-group';
import { MemberBucketEncryption } from './member/bucket-encryption';
import { MemberVersion } from './member/version';
import { SerializedNestedStackFactory } from './cdk-helper/nested-stack';
import { WaitProvider } from './wait-provider';

export interface SolutionProps extends StackProps {
  solutionId: string;
  solutionDistBucket: string;
  solutionTMN: string;
  solutionVersion: string;
  runtimePython: Runtime;
}

export class MemberStack extends Stack {
  nestedStacks: Stack[] = [];
  constructor(scope: App, id: string, props: SolutionProps) {
    super(scope, id, props);

    const adminAccountParam = new AdminAccountParam(this, 'AdminAccountParameter');

    new RedshiftAuditLogging(this, 'RedshiftAuditLogging', { solutionId: props.solutionId });

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

    this.nestedStacks.push(nestedStackNoRoles as Stack);

    const playbookDirectory = `${__dirname}/../playbooks`;
    const ignore = ['.DS_Store', 'common', '.pytest_cache', 'NEWPLAYBOOK', '.coverage'];
    const illegalChars = /[\\._]/g;
    const listOfPlaybooks: string[] = [];
    const items = readdirSync(playbookDirectory);
    items.forEach((file) => {
      if (!ignore.includes(file)) {
        const templateFile = `${file}MemberStack.template`;

        const parmname = file.replace(illegalChars, '');
        const memberStackOption = new CfnParameter(this, `LoadMemberStack${parmname}`, {
          type: 'String',
          description: `Load Playbook member stack for ${file}?`,
          default: 'yes',
          allowedValues: ['yes', 'no'],
        });
        memberStackOption.overrideLogicalId(`Load${parmname}MemberStack`);
        listOfPlaybooks.push(memberStackOption.logicalId);

        const nestedStack = nestedStackFactory.addNestedStack(`PlaybookMemberStack${file}`, {
          templateRelativePath: `playbooks/${templateFile}`,
          parameters: {
            SecHubAdminAccount: adminAccountParam.value,
            WaitProviderServiceToken: waitProvider.serviceToken,
          },
          condition: new CfnCondition(this, `load${file}Cond`, {
            expression: Fn.conditionEquals(memberStackOption, 'yes'),
          }),
        });
        const cfnResource = nestedStack.nestedStackResource as CfnResource;
        cfnResource.overrideLogicalId(`PlaybookMemberStack${file}`);
        this.nestedStacks.push(nestedStack as Stack);
      }
    });

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
            Label: { default: 'Playbooks' },
            Parameters: listOfPlaybooks,
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
