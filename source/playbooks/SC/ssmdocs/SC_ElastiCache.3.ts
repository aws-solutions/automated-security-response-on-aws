// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableElastiCacheReplicationGroupFailover(scope, id, { ...props, controlId: 'ElastiCache.3' });
}

export class EnableElastiCacheReplicationGroupFailover extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'ElastiCache.3',
      remediationName: 'EnableElastiCacheReplicationGroupFailover',
      scope: RemediationScope.REGIONAL,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):elasticache:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):(?:\d{12}):replicationgroup:([a-zA-Z](?:(?!--)[a-zA-Z0-9-]){0,48}[a-zA-Z0-9]$|[a-zA-Z]$)`,
      resourceIdName: 'GroupId',
      updateDescription: new StringFormat('Automatic failover enabled for replication group %s.', [
        StringVariable.of(`ParseInput.GroupId`),
      ]),
    });
  }
}
