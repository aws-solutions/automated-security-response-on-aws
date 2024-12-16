// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CreateCloudTrailMultiRegionTrailDocument(scope, id, {
    ...props,
    controlId: 'CloudTrail.1',
    otherControlIds: ['CloudTrail.3'],
  });
}

export class CreateCloudTrailMultiRegionTrailDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'CloudTrail.1',
      remediationName: 'CreateCloudTrailMultiRegionTrail',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Multi-region, encrypted AWS CloudTrail successfully created'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.AWSPartition = StringVariable.of('global:AWS_PARTITION');

    return params;
  }
}
