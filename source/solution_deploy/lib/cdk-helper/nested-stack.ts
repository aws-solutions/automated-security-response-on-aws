// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnMapping, CfnStack } from 'aws-cdk-lib';
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

export class SerializedNestedStackFactory extends Construct {
  private readonly scope: Construct;
  private readonly mapping: CfnMapping;
  private readonly mappingKey = 'General';
  private readonly bucketKey = 'S3Bucket';
  private readonly keyPrefixKey = 'KeyPrefix';
  private unconditionalNestedStacks: CfnStack[] = [];
  private conditionalNestedStacks: CfnStack[] = [];

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

  addNestedStack(id: string, props: NestedStackProps): CfnStack {
    const templateUrl =
      'https://' +
      this.mapping.findInMap(this.mappingKey, this.bucketKey) +
      '-reference.s3.amazonaws.com/' +
      this.mapping.findInMap(this.mappingKey, this.keyPrefixKey) +
      '/' +
      props.templateRelativePath;

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    const stack = new CfnStack(this.scope, id, { templateUrl, parameters: props.parameters });

    // TODO set up serial dependency structure

    if (props.condition) {
      setCondition(stack, props.condition);
      this.conditionalNestedStacks.push(stack);
    } else {
      this.unconditionalNestedStacks.push(stack);
    }

    return stack;
  }
}
