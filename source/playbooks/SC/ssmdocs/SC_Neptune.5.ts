// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable, NumberVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableNeptuneDbBackupRetentionPeriodDocument(scope, id, { ...props, controlId: 'Neptune.5' });
}

export class EnableNeptuneDbBackupRetentionPeriodDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'Neptune.5',
      remediationName: 'EnableNeptuneDbBackupRetentionPeriod',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DbClusterResourceId',
      resourceIdRegex: String.raw`^cluster-[a-zA-Z0-9-]{1,1016}$`,
      updateDescription: HardCodedString.of('This document will use the Amazon Neptune ModifyDBCluster API to enable automated backups with a backup retention period between 7 and 35 days for the specified Amazon Neptune DB cluster.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DbClusterResourceId = StringVariable.of('ParseInput.DbClusterResourceId');
    params.BackupRetentionPeriod = NumberVariable.of('ParseInput.BackupRetentionPeriod');
    params.PreferredBackupWindow = StringVariable.of('ParseInput.PreferredBackupWindow'); //Optional

    return params;
  }
}