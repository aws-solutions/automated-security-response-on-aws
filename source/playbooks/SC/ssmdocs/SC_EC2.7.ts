// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableEbsEncryptionByDefaultDocument(scope, id, { ...props, controlId: 'EC2.7' });
}

export class EnableEbsEncryptionByDefaultDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.7',
      remediationName: 'EnableEbsEncryptionByDefault',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Enabled EBS encryption by default'),
    });
  }
}
