// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { EnableRDSClusterDeletionProtectionDocument } from '../../SC/ssmdocs/SC_RDS.7';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableRDSClusterDeletionProtectionDocument(stage, id, { ...props, controlId: 'RDS.7' });
}
