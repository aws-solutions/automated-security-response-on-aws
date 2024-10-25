// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3BucketVersioningDocument(scope, id, { ...props, controlId: 'S3.14' });
}

class ConfigureS3BucketVersioningDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.14',
      remediationName: 'ConfigureS3BucketVersioning',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'BucketName',
      resourceIdRegex: String.raw`^(?!.*\.\.)(?!.*\.$)[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]$`,
      updateDescription: HardCodedString.of('This document configures versioning for an Amazon Simple Storage Service (Amazon S3) bucket.'),
    });
  }
  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.BucketName = StringVariable.of('ParseInput.BucketName');
    params.VersioningState = StringVariable.of('ParseInput.VersioningState'); // optional

    return params;
  }
}
