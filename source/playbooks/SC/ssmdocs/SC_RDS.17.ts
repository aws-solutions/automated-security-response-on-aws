// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { 
    HardCodedString, 
    StringVariable, 
    BooleanVariable, 
    NumberVariable 
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCopyTagsToSnapshotOnRDSDBInstanceDocument(scope, id, { ...props, controlId: 'RDS.17' });
}

class EnableCopyTagsToSnapshotOnRDSDBInstanceDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.17',
      remediationName: 'EnableCopyTagsToSnapshotOnRDSDBInstance',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DbiResourceId',
      resourceIdRegex: String.raw`^db-[A-Z0-9]+$`,
      updateDescription: HardCodedString.of('The document enables CopyTagsToSnapshot on a given Amazon RDS database instance using the ModifyDBInstance API.'),
    });
  }
   /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DbiResourceId = StringVariable.of('ParseInput.DbiResourceId');
    params.ApplyImmediately = BooleanVariable.of('ParseInput.ApplyImmediately'); // optional
    params.BackupRetentionPeriod = BooleanVariable.of('ParseInput.BackupRetentionPeriod');
    params.PreferredBackupWindow = NumberVariable.of('ParseInput.PreferredBackupWindow'); // optional

    return params;
  }
}
