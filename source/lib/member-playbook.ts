// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CfnParameter, CfnResource, Fn, Stack } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { SerializedNestedStackFactory } from './cdk-helper/nested-stack';

export interface MemberPlaybookProps {
  readonly name: string;
  readonly nestedStackFactory: SerializedNestedStackFactory;
  readonly totalControls: number;
  readonly parameters?: Record<string, string>;
  readonly stackDependencies?: CfnResource[];
  readonly defaultState?: 'yes' | 'no';
  readonly description?: string;
  readonly stackLimit?: number;
}

export class MemberPlaybook {
  parameterName = '';
  playbookPrimaryStack: Stack;
  playbookOverflowStacks: Stack[];
  stackOption: CfnParameter;

  constructor(scope: Construct, props: MemberPlaybookProps) {
    const templateFile = `${props.name}MemberStack.template`;
    const logicalId = `PlaybookMemberStack${props.name}`;
    const illegalChars = /[\\._]/g;
    const playbookName = props.name.replace(illegalChars, '');
    this.parameterName = `Load${playbookName}MemberStack`;
    this.playbookOverflowStacks = [];

    //---------------------------------------------------------------------
    // Playbook Template Nested Stack
    //
    this.stackOption = new CfnParameter(scope, `LoadMemberStack${playbookName}`, {
      type: 'String',
      description:
        props.description ?? `Install the member components for automated remediation of ${props.name} controls?`,
      default: props.defaultState ?? 'no',
      allowedValues: ['yes', 'no'],
    });
    this.stackOption.overrideLogicalId(this.parameterName);

    this.playbookPrimaryStack = this.createPlaybookStack(templateFile, playbookName, logicalId, scope, props);

    if (props.stackLimit) {
      const numDivisions = Math.ceil(props.totalControls / props.stackLimit);
      for (let stackIndex = 1; stackIndex < numDivisions; stackIndex++) {
        const splitPlaybookStack = this.createPlaybookStack(
          `${props.name}MemberStack${stackIndex}.template`,
          `${playbookName}${stackIndex}`,
          `${logicalId}${stackIndex}`,
          scope,
          props,
        );
        this.playbookOverflowStacks.push(splitPlaybookStack);
      }
    }
  }

  private createPlaybookStack(
    templateFile: string,
    playbookName: string,
    logicalId: string,
    scope: Construct,
    props: MemberPlaybookProps,
  ) {
    const playbookStack = props.nestedStackFactory.addNestedStack(`PlaybookMemberStack${playbookName}`, {
      templateRelativePath: `playbooks/${templateFile}`,
      parameters: props.parameters,
      condition: new CfnCondition(scope, `load${playbookName}Cond`, {
        expression: Fn.conditionEquals(this.stackOption, 'yes'),
      }),
    });

    const cfnStack = playbookStack.nestedStackResource as CfnResource;
    cfnStack.overrideLogicalId(logicalId);
    return playbookStack;
  }
}
