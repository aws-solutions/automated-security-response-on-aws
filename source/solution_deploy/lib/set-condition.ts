// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnCondition, CfnResource } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

export default function setCondition(resource: IConstruct, condition: CfnCondition): void {
  const cfnResource = resource.node.defaultChild as CfnResource;
  const oldCondition = cfnResource?.cfnOptions?.condition;
  if (oldCondition) {
    throw new Error(`Resource ${cfnResource?.logicalId} already has a condition: ${oldCondition.logicalId}`);
  }
  if (!cfnResource?.cfnOptions) {
    throw new Error(`Resource ${cfnResource?.logicalId} has no cfnOptions, unable to add condition`);
  }
  cfnResource.cfnOptions.condition = condition;
}
