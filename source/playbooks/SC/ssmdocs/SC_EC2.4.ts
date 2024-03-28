// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import {
  HardCodedString,
  DocumentOutput,
  DataTypeEnum,
  StringVariable,
  StringFormat,
  StringListVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new TerminateEC2InstanceDocument(stage, id, { ...props, controlId: 'EC2.4' });
}

export class TerminateEC2InstanceDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'EC2.4',
      remediationName: 'TerminateEC2Instance',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'InstanceId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:instance\/(i-[0-9a-f]*)$`,
      updateDescription: HardCodedString.of('Terminated EC2 instance.'),
    });
  }

  solutionAcronym = 'AWS';

  docOutputs = this.getOutputs();

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = {
      AutomationAssumeRole: new StringFormat(`arn:%s:iam::%s:role/%s`, [
        StringVariable.of('global:AWS_PARTITION'),
        StringVariable.of('global:ACCOUNT_ID'),
        StringVariable.of('RemediationRoleName'),
      ]),
    };

    // Pass the resource ID only if used
    if (this.resourceIdName) {
      params[this.resourceIdName] = [StringListVariable.of(`ParseInput.${this.resourceIdName}`)];
    }

    return params;
  }

  /** @override */
  protected getOutputs(): DocumentOutput[] {
    return [{ name: 'ParseInput.AffectedObject', outputType: DataTypeEnum.STRING_MAP }];
  }
}
