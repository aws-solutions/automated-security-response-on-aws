// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, HardCodedString, NumberVariable, Output } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new AttachServiceVPCEndpointDocument(scope, id, { ...props, controlId: 'EC2.10' });
}

export class AttachServiceVPCEndpointDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'EC2.10',
      remediationName: 'AttachServiceVPCEndpoint',
      scope: RemediationScope.REGIONAL,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:.*:\d{12}:vpc/(vpc-[0-9a-f]{8,17})$`,
      resourceIdName: 'VPCId',
      updateDescription: HardCodedString.of('Service Endpoint created and attached to VPC.'),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        serviceName: 'ec2',
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const ServiceName: Output = {
      name: 'ServiceName',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.serviceName',
    };

    return [ServiceName];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.ServiceName = NumberVariable.of('GetInputParams.ServiceName');

    return params;
  }
}
