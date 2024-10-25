// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable, NumberVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDynamoDbAutoscalingDocument(scope, id, { ...props, controlId: 'DynamoDB.1' });
}

export class EnableDynamoDbAutoscalingDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'DynamoDB.1',
      remediationName: 'EnableDynamoDbAutoscalingDocument',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TableName',
      resourceIdRegex: String.raw`[a-zA-Z0-9_.-]{3,255}`,
      updateDescription: HardCodedString.of('Enables Application Auto Scaling for the provisioned capacity Amazon DynamoDB table you specify.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.TableName = StringVariable.of('ParseInput.TableName');
    params.MinReadCapacity = NumberVariable.of('ParseInput.MinReadCapacity');
    params.MaxReadCapacity = NumberVariable.of('ParseInput.MaxReadCapacity');
    params.TargetReadCapacityUtilization = NumberVariable.of('ParseInput.TargetReadCapacityUtilization');
    params.ReadScaleOutCooldown = NumberVariable.of('ParseInput.ReadScaleOutCooldown');
    params.ReadScaleInCooldown = NumberVariable.of('ParseInput.ReadScaleInCooldown');
    params.MinWriteCapacity = NumberVariable.of('ParseInput.MinWriteCapacity');
    params.MaxWriteCapacity = NumberVariable.of('ParseInput.MaxWriteCapacity');
    params.TargetWriteCapacityUtilization = NumberVariable.of('ParseInput.TargetWriteCapacityUtilization');
    params.WriteScaleOutCooldown = NumberVariable.of('ParseInput.WriteScaleOutCooldown');
    params.WriteScaleInCooldown = NumberVariable.of('ParseInput.WriteScaleInCooldown');

    return params;
  }
}