// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableKeyRotationDocument(scope, id, { ...props, controlId: 'KMS.4' });
}

export class EnableKeyRotationDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const resourceIdName = 'KeyId';

    super(scope, id, {
      ...props,
      securityControlId: 'KMS.4',
      remediationName: 'EnableKeyRotation',
      scope: RemediationScope.REGIONAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:key\/([A-Za-z0-9-]{36})$`,
      updateDescription: new StringFormat('Enabled KMS Customer Managed Key rotation for %s', [
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }
}
