// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveUnrestrictedSourceIngressRules(scope, id, { ...props, controlId: 'EC2.19' });
}

export class RemoveUnrestrictedSourceIngressRules extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.19',
      remediationName: 'RemoveUnrestrictedSourceIngressRules',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'SecurityGroupId',
      updateDescription: HardCodedString.of('Replaces all ingress rules from the security group you specify that allow traffic from all source addresse.'),
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group\/(sg-[0-9a-f]*)$`
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs: Output[] = super.getParseInputStepOutputs();

    outputs.push({
      name: 'IpRanges',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.ipranges',
    });

    outputs.push({
      name: 'AllowedPort',
      outputType: DataTypeEnum.STRING_LIST,
      selector: '$.Payload.allowed_ports',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params: { [_: string]: any } = super.getRemediationParams();
    // TODO: It should be parameterized
    params.IpRanges = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    params.AllowedPort = ["20", "21" ,"22" ,"23" ,"25" ,"110" ,"135" ,"143" ,"445", "1433", "1434" ,"3000" ,"3306" ,"3389" ,"4333" ,"5000" ,"5432" ,"5500" ,"5601" ,"8080" ,"8088" ,"8888" ,"9200", "9300" ]
    return params;
  }
}
