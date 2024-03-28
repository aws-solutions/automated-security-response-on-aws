// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableVPCFlowLogsDocument(scope, id, { ...props, controlId: 'EC2.6' });
}

export class EnableVPCFlowLogsDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.6',
      remediationName: 'EnableVPCFlowLogs',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'VPC',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:.*:\d{12}:vpc\/(vpc-[0-9a-f]{8,17})$`,
      updateDescription: HardCodedString.of('Enabled VPC Flow logging.'),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.RemediationRole = new StringFormat(
      `arn:%s:iam::%s:role/${this.solutionId}-EnableVPCFlowLogs-remediationRole`,
      [StringVariable.of('global:AWS_PARTITION'), StringVariable.of('global:ACCOUNT_ID')],
    );

    return params;
  }
}
