// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as lambda from 'aws-cdk-lib/aws-lambda';

/**
 * @description Remove tags from EventSourceMappings attached to a Lambda function
 * @param lambdaFunction The Lambda function to clean EventSourceMapping tags from
 */
export function removeEventSourceMappingTags(lambdaFunction: lambda.Function): void {
  const eventSourceMappings = lambdaFunction.node.children.filter(
    (child) => child.node.defaultChild instanceof lambda.CfnEventSourceMapping,
  );

  if (eventSourceMappings.length > 0) {
    const cfnEventSourceMapping = eventSourceMappings[0].node.defaultChild as lambda.CfnEventSourceMapping;
    cfnEventSourceMapping.addPropertyOverride('Tags', undefined);
  }
}
