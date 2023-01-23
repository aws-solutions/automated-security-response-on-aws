// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CloudTrail_4_ControlRunbookDocument(scope, id, { ...props, controlId: 'CloudTrail.4' });
}

export class CloudTrail_4_ControlRunbookDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CloudTrail.4',
      remediationName: 'EnableCloudTrailLogFileValidation',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TrailName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:trail\/([A-Za-z0-9._-]{3,128})$`,
      updateDescription: HardCodedString.of('Enabled CloudTrail log file validation.'),
    });
  }
}
