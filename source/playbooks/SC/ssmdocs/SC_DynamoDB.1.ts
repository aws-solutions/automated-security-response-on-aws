// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { AutomationStep, DataTypeEnum, Output, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureDynamoDBAutoScaling(scope, id, { ...props, controlId: 'DynamoDB.1' });
}

export class ConfigureDynamoDBAutoScaling extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'DynamoDB.1',
      remediationName: 'ConfigureDynamoDBAutoScaling',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TableId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):dynamodb:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):(?:\d{12}):table\/([a-zA-Z0-9._-]{3,255})$`,
      updateDescription: new StringFormat('Configured auto scaling for table %s.', [
        StringVariable.of(`ParseInput.TableId`),
      ]),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        minProvisionedReadCapacity: '5',
        minProvisionedWriteCapacity: '5',
        targetReadUtilization: '70',
        targetWriteUtilization: '70',
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const minProvisionedReadCapacity: Output = {
      name: 'MinProvisionedReadCapacity',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.minProvisionedReadCapacity',
    };

    const targetReadUtilization: Output = {
      name: 'TargetReadUtilization',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.targetReadUtilization',
    };

    const minProvisionedWriteCapacity: Output = {
      name: 'MinProvisionedWriteCapacity',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.minProvisionedWriteCapacity',
    };

    const targetWriteUtilization: Output = {
      name: 'TargetWriteUtilization',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.targetWriteUtilization',
    };

    return [minProvisionedReadCapacity, minProvisionedWriteCapacity, targetReadUtilization, targetWriteUtilization];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.MinProvisionedReadCapacity = StringVariable.of('GetInputParams.MinProvisionedReadCapacity');
    params.TargetReadUtilization = StringVariable.of('GetInputParams.TargetReadUtilization');
    params.MinProvisionedWriteCapacity = StringVariable.of('GetInputParams.MinProvisionedWriteCapacity');
    params.TargetWriteUtilization = StringVariable.of('GetInputParams.TargetWriteUtilization');

    return params;
  }
}
