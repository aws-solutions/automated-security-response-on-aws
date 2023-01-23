// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedBoolean, HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new S3_1_ControlRunbookDocument(scope, id, { ...props, controlId: 'S3.1' });
}

class S3_1_ControlRunbookDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.1',
      remediationName: 'ConfigureS3PublicAccessBlock',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Configured the account to block public S3 access.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.AccountId = StringVariable.of('ParseInput.RemediationAccount');
    params.RestrictPublicBuckets = HardCodedBoolean.TRUE;
    params.BlockPublicAcls = HardCodedBoolean.TRUE;
    params.IgnorePublicAcls = HardCodedBoolean.TRUE;
    params.BlockPublicPolicy = HardCodedBoolean.TRUE;

    return params;
  }
}
