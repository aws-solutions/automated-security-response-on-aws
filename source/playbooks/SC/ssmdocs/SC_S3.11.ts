// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  HardCodedString,
  Output,
  StringListVariable,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableBucketEventNotificationsDocument(scope, id, { ...props, controlId: 'S3.11' });
}

export class EnableBucketEventNotificationsDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.11',
      remediationName: 'EnableBucketEventNotifications',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Configured event notifications to an S3 Bucket.'),
    });
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        eventTypes: [
          's3:ReducedRedundancyLostObject',
          's3:ObjectCreated:*',
          's3:ObjectRemoved:*',
          's3:ObjectRestore:*',
          's3:Replication:*',
          's3:LifecycleExpiration:*',
          's3:LifecycleTransition',
          's3:IntelligentTiering',
          's3:ObjectTagging:*',
          's3:ObjectAcl:Put',
        ],
      }),
    ];
  }

  /** @override */
  protected getInputParamsStepOutput(): Output[] {
    const EventTypes: Output = {
      name: 'eventTypes',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.eventTypes',
    };

    const outputs: Output[] = [EventTypes];

    return outputs;
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.AccountId = StringVariable.of('ParseInput.RemediationAccount');
    params.EventTypes = StringListVariable.of('GetInputParams.eventTypes');

    return params;
  }
}
