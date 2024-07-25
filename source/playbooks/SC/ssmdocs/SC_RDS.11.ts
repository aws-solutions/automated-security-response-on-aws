// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable, BooleanVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableRDSInstanceBackupDocument(scope, id, { ...props, controlId: 'RDS.11' });
}

class EnableRDSInstanceBackupDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.11',
      remediationName: 'EnableRDSInstanceBackup',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DbiResourceId',
      resourceIdRegex: String.raw`^db-[A-Z0-9]+$`,
      updateDescription: HardCodedString.of('The document enables backups for the Amazon Relational Database Service (Amazon RDS) database instance you specify.'),
    });
  }
   /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DbiResourceId = StringVariable.of('ParseInput.DbiResourceId');
    params.ApplyImmediately = BooleanVariable.of('ParseInput.ApplyImmediately'); // optional

    return params;
  }
}