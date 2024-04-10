// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CfnParameter, CfnResource, Fn, NestedStack, Stack } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface AdminPlaybookProps {
  name: string;
  stackDependencies?: CfnResource[];
  defaultState?: 'yes' | 'no';
  description?: string;
}

export class AdminPlaybook {
  parameterName = '';
  playbookStack: Stack;

  constructor(scope: Construct, props: AdminPlaybookProps) {
    const templateFile = `${props.name}Stack.template`;
    const illegalChars = /[\\._]/g;
    const playbookName = props.name.replace(illegalChars, '');
    this.parameterName = `Load${playbookName}AdminStack`;

    //---------------------------------------------------------------------
    // Playbook Template Nested Stack
    //
    const stackOption = new CfnParameter(scope, `LoadAdminStack${playbookName}`, {
      type: 'String',
      description:
        props.description ?? `Install the admin components for automated remediation of ${props.name} controls?`,
      default: props.defaultState ?? 'no',
      allowedValues: ['yes', 'no'],
    });
    stackOption.overrideLogicalId(this.parameterName);

    this.playbookStack = new NestedStack(scope, `PlaybookAdminStack${playbookName}`);
    const cfnStack = this.playbookStack.nestedStackResource as CfnResource;
    cfnStack.addPropertyOverride(
      'TemplateURL',
      'https://' +
        Fn.findInMap('SourceCode', 'General', 'S3Bucket') +
        '-reference.s3.amazonaws.com/' +
        Fn.findInMap('SourceCode', 'General', 'KeyPrefix') +
        '/playbooks/' +
        templateFile,
    );
    cfnStack.cfnOptions.condition = new CfnCondition(scope, `load${playbookName}Cond`, {
      expression: Fn.conditionEquals(stackOption, 'yes'),
    });
    props.stackDependencies?.forEach((dependency) => {
      cfnStack.node.addDependency(dependency);
    });
    cfnStack.overrideLogicalId(`PlaybookAdminStack${props.name}`);
  }
}
