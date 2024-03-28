// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { HardCodedString, Output, DataTypeEnum, StringListVariable, AutomationStep } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RevokeUnauthorizedInboundRulesDocument(stage, id, { ...props, controlId: 'EC2.18' });
}

export class RevokeUnauthorizedInboundRulesDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'EC2.18',
      remediationName: 'RevokeUnauthorizedInboundRules',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'SecurityGroupId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group/(sg-[0-9a-f]*)$`,
      updateDescription: HardCodedString.of('Revoked unrestricted inbound security group rules on unauthorized ports.'),
    });
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        authorizedTcpPorts: ['80', '443'],
        authorizedUdpPorts: [],
      }),
    ];
  }

  /** @override */
  protected getInputParamsStepOutput(): Output[] {
    const AuthorizedTcpPorts: Output = {
      name: 'authorizedTcpPorts',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.authorizedTcpPorts',
    };
    const AuthorizedUdpPorts: Output = {
      name: 'authorizedUdpPorts',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.authorizedUdpPorts',
    };

    const outputs: Output[] = [AuthorizedTcpPorts, AuthorizedUdpPorts];

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.AuthorizedTcpPorts = StringListVariable.of('GetInputParams.authorizedTcpPorts');
    params.AuthorizedUdpPorts = StringListVariable.of('GetInputParams.authorizedUdpPorts');

    return params;
  }
}
