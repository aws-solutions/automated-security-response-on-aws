// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  AwsApiStep,
  AwsService,
  DataTypeEnum,
  HardCodedString,
  Output,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableEnhancedMonitoringOnRDSInstanceDocument(scope, id, { ...props, controlId: 'RDS.6' });
}

export class EnableEnhancedMonitoringOnRDSInstanceDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.6',
      remediationName: 'EnableEnhancedMonitoringOnRDSInstance',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Enhanced Monitoring enabled on RDS DB cluster'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DbiResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Details.AwsRdsDbInstance.DbiResourceId',
    });

    return outputs;
  }

  /** @override */
  protected getExtraSteps(): AutomationStep[] {
    return [
      new AwsApiStep(this, 'GetMonitoringRoleArn', {
        timeoutSeconds: 600,
        service: AwsService.IAM,
        pascalCaseApi: 'GetRole',
        apiParams: { RoleName: `${this.solutionId}-RDSMonitoring-remediationRole` },
        outputs: [
          {
            name: 'Arn',
            outputType: DataTypeEnum.STRING,
            selector: '$.Role.Arn',
          },
        ],
      }),
    ];
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.ResourceId = StringVariable.of('ParseInput.DbiResourceId');
    params.MonitoringRoleArn = StringVariable.of('GetMonitoringRoleArn.Arn');

    return params;
  }
}
