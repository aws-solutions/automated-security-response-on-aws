// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { EnableAutomaticSnapshotsOnRedshiftClusterDocument } from '../../SC/ssmdocs/SC_Redshift.3';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAutomaticSnapshotsOnRedshiftClusterDocument(stage, id, { ...props, controlId: 'Redshift.3' });
}
