// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAthenaWorkGroupLoggingDocument(scope, id, { ...props, controlId: 'Athena.4' });
}

export class EnableAthenaWorkGroupLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'Athena.4',
      remediationName: 'EnableAthenaWorkGroupLogging',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'WorkGroupName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):athena:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:workgroup\/(.+)$`,
      updateDescription: HardCodedString.of('Work Group logging enabled.'),
    });
  }
}
