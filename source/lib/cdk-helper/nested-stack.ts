// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnMapping, CfnStack, CfnWaitConditionHandle, Fn, NestedStack } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import setCondition from './set-condition';

export interface NestedStackFactoryProps {
  readonly solutionDistBucket: string;
  readonly solutionTMN: string;
  readonly solutionVersion: string;
}

export interface NestedStackProps {
  readonly templateRelativePath: string;
  readonly parameters?: { [_: string]: string };
  readonly condition?: CfnCondition;
}

interface ConditionalNestedStack {
  readonly stack: CfnStack;
  readonly condition: CfnCondition;
}

export class SerializedNestedStackFactory extends Construct {
  private readonly scope: Construct;
  private readonly mapping: CfnMapping;
  private readonly mappingKey = 'General';
  private readonly bucketKey = 'S3Bucket';
  private readonly keyPrefixKey = 'KeyPrefix';
  private unconditionalNestedStacks: CfnStack[] = [];
  private conditionalNestedStacks: ConditionalNestedStack[] = [];

  constructor(scope: Construct, id: string, props: NestedStackFactoryProps) {
    super(scope, id);

    this.scope = scope;
    this.mapping = new CfnMapping(this, 'SourceCode', {
      mapping: {
        [this.mappingKey]: {
          [this.bucketKey]: props.solutionDistBucket,
          [this.keyPrefixKey]: props.solutionTMN + '/' + props.solutionVersion,
        },
      },
    });
  }

  addNestedStack(id: string, props: NestedStackProps): NestedStack {
    const templateUrl =
      'https://' +
      this.mapping.findInMap(this.mappingKey, this.bucketKey) +
      '-reference.s3.amazonaws.com/' +
      this.mapping.findInMap(this.mappingKey, this.keyPrefixKey) +
      '/' +
      props.templateRelativePath;

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    const stack = new NestedStack(this.scope, id, { parameters: props.parameters });
    const cfnStack = stack.nestedStackResource as CfnStack;
    cfnStack.addPropertyOverride('TemplateURL', templateUrl);

    this.unconditionalNestedStacks.forEach(function (previousStack: CfnStack) {
      cfnStack.addDependency(previousStack);
    });

    if (this.conditionalNestedStacks.length > 0) {
      const dummyResource = new CfnWaitConditionHandle(this, `Gate${id}`);
      this.conditionalNestedStacks.forEach(function (previousStack: ConditionalNestedStack) {
        dummyResource.addMetadata(
          `${previousStack.stack.logicalId}Ready`,
          Fn.conditionIf(previousStack.condition.logicalId, Fn.ref(previousStack.stack.logicalId), ''),
        );
      });
      cfnStack.addDependency(dummyResource);
    }

    if (props.condition) {
      setCondition(cfnStack, props.condition);
      this.conditionalNestedStacks.push({ stack: cfnStack, condition: props.condition });
    } else {
      this.unconditionalNestedStacks.push(cfnStack);
    }

    return stack;
  }
}
