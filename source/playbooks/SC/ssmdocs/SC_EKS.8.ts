// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CollectEKSInstanceLogsDocument(scope, id, { ...props, controlId: 'EKS.8' });
}

export class CollectEKSInstanceLogsDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'EKS.8',
      remediationName: 'CollectEKSInstanceLogs',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'EKSInstanceId',
      resourceIdRegex: String.raw`^[i|mi]-[a-z0-9]{8,17}$`,
      updateDescription: HardCodedString.of('This document will collect EKS specific logs from the specified EC2 instance and upload it to a specified S3 bucket.'),
    });
  }
  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.EKSInstanceId = StringVariable.of('ParseInput.EKSInstanceId');
    params.LogDestination = StringVariable.of('ParseInput.LogDestination'); // optional

    return params;
  }
}