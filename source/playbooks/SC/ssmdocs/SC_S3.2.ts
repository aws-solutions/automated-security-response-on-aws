// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedBoolean, HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3BucketPublicAccessBlockDocument(scope, id, {
    ...props,
    controlId: 'S3.2',
    otherControlIds: ['S3.3', 'S3.8'],
  });
}

export class ConfigureS3BucketPublicAccessBlockDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.2',
      remediationName: 'ConfigureS3BucketPublicAccessBlock',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$`,
      updateDescription: HardCodedString.of('Disabled public access to S3 bucket.'),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.BucketName = StringVariable.of('ParseInput.BucketName');
    params.RestrictPublicBuckets = HardCodedBoolean.TRUE;
    params.BlockPublicAcls = HardCodedBoolean.TRUE;
    params.IgnorePublicAcls = HardCodedBoolean.TRUE;
    params.BlockPublicPolicy = HardCodedBoolean.TRUE;

    return params;
  }
}
