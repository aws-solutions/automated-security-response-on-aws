// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableSSMDocumentBlockPublicSharing(scope, id, { ...props, controlId: 'SSM.7' });
}

export class EnableSSMDocumentBlockPublicSharing extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'SSM.7',
      remediationName: 'EnableSSMDocumentBlockPublicSharing',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'AccountId',
      resourceIdRegex: '^AWS::::Account:(\\d{12})$',
      updateDescription: HardCodedString.of('Enabled block public sharing setting for SSM documents'),
    });
  }
}
