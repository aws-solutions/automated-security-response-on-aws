// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3BucketPublicAccessBlockDocument(scope, id, { ...props, controlId: 'CloudTrail.6' });
}

export class ConfigureS3BucketPublicAccessBlockDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'CloudTrail.6',
      remediationName: 'ConfigureS3BucketPublicAccessBlock',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Disabled public access to CloudTrail logs bucket.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.RestrictPublicBuckets = true;
    params.BlockPublicAcls = true;
    params.IgnorePublicAcls = true;
    params.BlockPublicPolicy = true;

    return params;
  }
}
