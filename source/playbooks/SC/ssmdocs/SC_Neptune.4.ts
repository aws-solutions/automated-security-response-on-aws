// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableNeptuneClusterDeletionProtectionDocument(scope, id, { ...props, controlId: 'Neptune.4' });
}

export class EnableNeptuneClusterDeletionProtectionDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'Neptune.4',
      remediationName: 'EnableNeptuneDbClusterDeletionProtection',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DbClusterResourceId',
      resourceIdRegex: String.raw`^cluster-[a-zA-Z0-9-]{1,1016}$`,
      updateDescription: HardCodedString.of('This document enables deletion protection for the Amazon Neptune cluster you specify.'),
    });
  }
}