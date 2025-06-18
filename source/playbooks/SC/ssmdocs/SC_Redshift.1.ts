// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicAccessToRedshiftClusterDocument(scope, id, { ...props, controlId: 'Redshift.1' });
}

export class DisablePublicAccessToRedshiftClusterDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Redshift.1',
      remediationName: 'DisablePublicAccessToRedshiftCluster',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ClusterIdentifier',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):redshift:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:cluster:(?!.*--)([a-z][a-z0-9-]{0,62})(?<!-)$`,
      updateDescription: HardCodedString.of('Disabled public access to Redshift cluster'),
    });
  }
}
