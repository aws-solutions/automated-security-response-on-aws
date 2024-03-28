// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import {
  AutomationStep,
  DataTypeEnum,
  HardCodedString,
  NumberVariable,
  Output,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetS3LifecyclePolicyDocument(stage, id, { ...props, controlId: 'S3.13' });
}

export class SetS3LifecyclePolicyDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'S3.13',
      remediationName: 'SetS3LifecyclePolicy',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([a-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Setting an example lifecycle policy on the S3 bucket.'),
    });
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        targetTransitionDays: 30,
        targetExpirationDays: 0,
        targetTransitionStorageClass: 'INTELLIGENT_TIERING',
      }),
    ];
  }

  /** @override */
  protected getInputParamsStepOutput(): Output[] {
    const TargetTransitionDays: Output = {
      name: 'targetTransitionDays',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.targetTransitionDays',
    };
    const TargetExpirationDays: Output = {
      name: 'targetExpirationDays',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.targetExpirationDays',
    };
    const TargetTransitionStorageClass: Output = {
      name: 'targetTransitionStorageClass',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.targetTransitionStorageClass',
    };

    const outputs: Output[] = [TargetTransitionDays, TargetExpirationDays, TargetTransitionStorageClass];

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.TargetTransitionDays = NumberVariable.of('GetInputParams.targetTransitionDays');
    params.TargetExpirationDays = NumberVariable.of('GetInputParams.targetExpirationDays');
    params.TargetTransitionStorageClass = StringVariable.of('GetInputParams.targetTransitionStorageClass');

    return params;
  }
}
