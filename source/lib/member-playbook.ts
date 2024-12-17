// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CfnParameter, CfnResource, Fn, Stack } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { SerializedNestedStackFactory } from './cdk-helper/nested-stack';

export interface MemberPlaybookProps {
  readonly name: string;
  readonly nestedStackFactory: SerializedNestedStackFactory;
  readonly parameters?: { [_: string]: string };
  readonly stackDependencies?: CfnResource[];
  readonly defaultState?: 'yes' | 'no';
  readonly description?: string;
}

export class MemberPlaybookNew {
  parameterName = '';
  playbookStacks: Stack[];

  constructor(scope: Construct, props: MemberPlaybookProps) {
    const templateFileOriginal = `${props.name}MemberStackOriginal.template`;
    const templateFileNew = `${props.name}MemberStackNew.template`;
    const illegalChars = /[\\._]/g;
    const playbookName = props.name.replace(illegalChars, '');
    this.parameterName = `Load${playbookName}MemberStacks`;

    //---------------------------------------------------------------------
    // Playbook Template Nested Stack
    //
    const stackOptionOriginal = new CfnParameter(scope, `LoadOriginalMemberStack${playbookName}`, {
      type: 'String',
      description:
        props.description ?? `Install the member components for automated remediation of ${props.name} controls?`,
      default: props.defaultState ?? 'no',
      allowedValues: ['yes', 'no'],
    });
    const stackOptionNew = new CfnParameter(scope, `LoadNewMemberStack${playbookName}`, {
      type: 'String',
      description:
        props.description ?? `Install the member components for automated remediation of ${props.name} controls?`,
      default: props.defaultState ?? 'no',
      allowedValues: ['yes', 'no'],
    });
    stackOptionOriginal.overrideLogicalId(this.parameterName);
      this.playbookStacks = []
      const originalNestedStack = props.nestedStackFactory.addNestedStack(`PlaybookMemberStackOriginal${playbookName}`, {
        templateRelativePath: `playbooks/${templateFileOriginal}`,
        parameters: props.parameters,
        condition: new CfnCondition(scope, `load${playbookName}CondOriginal`, {
          expression: Fn.conditionEquals(stackOptionOriginal, 'yes'),
        }),
      });

    const cfnStackOriginal = originalNestedStack.nestedStackResource as CfnResource;
    cfnStackOriginal.overrideLogicalId(`PlaybookMemberStackOriginal${props.name}`);

    const newNestedStack = props.nestedStackFactory.addNestedStack(`PlaybookMemberStackNew${playbookName}`, {
      templateRelativePath: `playbooks/${templateFileNew}`,
      parameters: props.parameters,
      condition: new CfnCondition(scope, `load${playbookName}CondNew`, {
        expression: Fn.conditionEquals(stackOptionNew, 'yes'),
      }),
    });

    const cfnStackNew = newNestedStack.nestedStackResource as CfnResource;
    cfnStackNew.overrideLogicalId(`PlaybookMemberStackNew${props.name}`);

    this.playbookStacks.push(originalNestedStack as Stack)
    this.playbookStacks.push(newNestedStack as Stack)
  }
}

export class MemberPlaybook {
  parameterName = '';
  playbookStack: Stack;

  constructor(scope: Construct, props: MemberPlaybookProps) {
    const templateFile = `${props.name}MemberStack.template`;
    const illegalChars = /[\\._]/g;
    const playbookName = props.name.replace(illegalChars, '');
    this.parameterName = `Load${playbookName}MemberStack`;

    //---------------------------------------------------------------------
    // Playbook Template Nested Stack
    //
    const stackOption = new CfnParameter(scope, `LoadMemberStack${playbookName}`, {
      type: 'String',
      description:
        props.description ?? `Install the member components for automated remediation of ${props.name} controls?`,
      default: props.defaultState ?? 'no',
      allowedValues: ['yes', 'no'],
    });
    stackOption.overrideLogicalId(this.parameterName);
    this.playbookStack = props.nestedStackFactory.addNestedStack(`PlaybookMemberStack${playbookName}`, {
      templateRelativePath: `playbooks/${templateFile}`,
      parameters: props.parameters,
      condition: new CfnCondition(scope, `load${playbookName}Cond`, {
        expression: Fn.conditionEquals(stackOption, 'yes'),
      }),
    });
    const cfnStack = this.playbookStack.nestedStackResource as CfnResource;
    cfnStack.overrideLogicalId(`PlaybookMemberStack${props.name}`);
  }
}
