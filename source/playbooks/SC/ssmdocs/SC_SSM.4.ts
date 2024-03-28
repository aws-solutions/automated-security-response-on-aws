// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicSSMDocument(scope, id, { ...props, controlId: 'SSM.4' });
}

export class DisablePublicSSMDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SSM.4',
      remediationName: 'BlockSSMDocumentPublicAccess',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DocumentArn',
      updateDescription: HardCodedString.of('SSM document changed from public to private'),
    });
  }
}
