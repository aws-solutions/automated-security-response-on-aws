// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableNeptuneDbAuditLogsToCloudWatchDocument(scope, id, { ...props, controlId: 'Neptune.2' });
}

export class EnableNeptuneDbAuditLogsToCloudWatchDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'Neptune.2',
      remediationName: 'EnableNeptuneDbAuditLogsToCloudWatch',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'DbClusterResourceId',
      resourceIdRegex: String.raw`^cluster-[a-zA-Z0-9-]{1,1016}$`,
      updateDescription: HardCodedString.of('This document will utilize the ModifyDBCluster API call to enable Amazon Neptune DB clusters to send audit logs to Amazon CloudWatch.'),
    });
  }
}