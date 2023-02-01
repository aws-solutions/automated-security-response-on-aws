// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnParameter } from 'aws-cdk-lib';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface MemberLogGroupProps {
  readonly solutionId: string;
}

export class MemberLogGroup extends Construct {
  public readonly paramId: string;

  constructor(scope: Construct, id: string, props: MemberLogGroupProps) {
    super(scope, id);

    // Create all resource at `scope` scope rather than `this` to maintain logical IDs

    const templateParam = new CfnParameter(scope, 'LogGroupName', {
      type: 'String',
      description:
        'Name of the log group to be used to create metric filters and cloudwatch alarms. You must use a Log Group that is the the logging destination of a multi-region CloudTrail',
    });
    this.paramId = templateParam.logicalId;

    new StringParameter(scope, 'SSMParameterLogGroupName', {
      description: 'Parameter to store log group name',
      parameterName: `/Solutions/${props.solutionId}/Metrics_LogGroupName`,
      stringValue: templateParam.valueAsString,
    });
  }
}
