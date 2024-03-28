// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnResource, Fn, IAspect } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

export class ConditionAspect<T extends new (...args: never[]) => CfnResource> implements IAspect {
  constructor(
    private condition: CfnCondition,
    private resourceType?: T,
  ) {}

  visit(node: IConstruct): void {
    if (node instanceof (this.resourceType ?? CfnResource)) {
      if (node.cfnOptions.condition) {
        const parentStack = node.cfnOptions.condition?.stack;
        const existingConditionName = parentStack.resolve(node.cfnOptions.condition).Condition;
        const newConditionName = parentStack.resolve(this.condition).Condition;
        if (existingConditionName !== newConditionName) {
          const combinedName = `${existingConditionName}And${newConditionName}`;

          const compoundCondition =
            (parentStack.node.tryFindChild(combinedName) as CfnCondition) ??
            new CfnCondition(parentStack, combinedName, {
              expression: Fn.conditionAnd(this.condition, node.cfnOptions.condition),
            });

          node.cfnOptions.condition = compoundCondition;
        }
      } else {
        node.cfnOptions.condition = this.condition;
      }
    }
  }
}
