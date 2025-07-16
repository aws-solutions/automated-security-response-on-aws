// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnResource } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

export function addCfnGuardSuppression(resource: IConstruct, suppression: string): void {
  const cfnResource = resource.node.defaultChild as CfnResource;
  if (!cfnResource?.cfnOptions) {
    throw new Error(`Resource ${cfnResource?.logicalId} has no cfnOptions, unable to add CfnGuard suppression`);
  }
  const existingSuppressions: string[] = cfnResource.cfnOptions.metadata?.guard?.SuppressedRules;
  if (existingSuppressions) {
    existingSuppressions.push(suppression);
  } else if (cfnResource.cfnOptions.metadata) {
    cfnResource.cfnOptions.metadata.guard = {
      SuppressedRules: [suppression],
    };
  } else {
    cfnResource.cfnOptions.metadata = {
      guard: {
        SuppressedRules: [suppression],
      },
    };
  }
}
