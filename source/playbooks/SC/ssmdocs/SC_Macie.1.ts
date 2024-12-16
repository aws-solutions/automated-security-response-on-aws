// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableMacieDocument(scope, id, { ...props, controlId: 'Macie.1' });
}

export class EnableMacieDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Macie.1',
      remediationName: 'EnableMacie',
      scope: RemediationScope.REGIONAL,
      updateDescription: new StringFormat('Enabled AWS Macie in account %s.', [
        StringVariable.of(`ParseInput.RemediationAccount`),
      ]),
    });
  }
}
