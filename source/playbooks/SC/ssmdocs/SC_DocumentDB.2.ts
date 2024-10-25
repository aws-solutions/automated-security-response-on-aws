// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable, NumberVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDocDbClusterBackupRetentionPeriodDocument(scope, id, { ...props, controlId: 'DocumentDB.2' });
}

export class EnableDocDbClusterBackupRetentionPeriodDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'DocumentDB.2',
      remediationName: 'EnableDocDbClusterBackupRetentionPeriod',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DBClusterResourceId',
      resourceIdRegex: String.raw`^[a-zA-Z0-9-]{1,1024}$`,
      updateDescription: HardCodedString.of('Verifies the retention period for the Amazon DocumentDB cluster and the preferred back up window, if specified, were successfully set.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DBClusterResourceId = StringVariable.of('ParseInput.DBClusterResourceId');
    params.BackupRetentionPeriod = NumberVariable.of('ParseInput.BackupRetentionPeriod');
    params.PreferredBackupWindow = StringVariable.of('ParseInput.PreferredBackupWindow'); // optional

    return params;
  }
}