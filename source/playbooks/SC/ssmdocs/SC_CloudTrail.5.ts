// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCloudTrailToCloudWatchLoggingDocument(scope, id, { ...props, controlId: 'CloudTrail.5' });
}

export class EnableCloudTrailToCloudWatchLoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'CloudTrail.5',
      remediationName: 'EnableCloudTrailToCloudWatchLogging',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TrailName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):cloudtrail:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:trail\/([A-Za-z0-9._-]{3,128})$`,
      updateDescription: new StringFormat('Configured CloudTrail logging to CloudWatch Logs Group CloudTrail/%s', [
        StringVariable.of('ParseInput.TrailName'),
      ]),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.CloudWatchLogsRole = new StringFormat(`arn:%s:iam::%s:role/${this.solutionId}-CloudTrailToCloudWatchLogs`, [
      StringVariable.of('global:AWS_PARTITION'),
      StringVariable.of('global:ACCOUNT_ID'),
    ]);
    params.LogGroupName = new StringFormat('CloudTrail/%s', [StringVariable.of('ParseInput.TrailName')]);

    return params;
  }
}
