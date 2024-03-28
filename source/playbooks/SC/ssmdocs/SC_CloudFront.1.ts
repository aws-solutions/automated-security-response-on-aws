// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudFrontDefaultRootObjectDocument(scope, id, { ...props, controlId: 'CloudFront.1' });
}

export class EnableCloudFrontDefaultRootObjectDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudFront.1',
      remediationName: 'EnableCloudFrontDefaultRootObject',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'CloudFrontDistribution',
      resourceIdRegex: String.raw`^(arn:(?:aws|aws-us-gov|aws-cn):cloudfront::\d{12}:distribution\/([A-Z0-9]+))$`,
      updateDescription: HardCodedString.of('Configured default root object for CloudFront distribution'),
    });
  }
}
