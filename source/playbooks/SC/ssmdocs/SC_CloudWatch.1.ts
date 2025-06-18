// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  ExecuteScriptStep,
  HardCodedString,
  Input,
  Output,
  ScriptCode,
  ScriptLanguage,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CreateLogMetricFilterAndAlarmDocument(scope, id, {
    ...props,
    controlId: 'CloudWatch.1',
    otherControlIds: [
      'CloudWatch.2',
      'CloudWatch.3',
      'CloudWatch.4',
      'CloudWatch.5',
      'CloudWatch.6',
      'CloudWatch.7',
      'CloudWatch.8',
      'CloudWatch.9',
      'CloudWatch.10',
      'CloudWatch.11',
      'CloudWatch.12',
      'CloudWatch.13',
      'CloudWatch.14',
    ],
  });
}

export class CreateLogMetricFilterAndAlarmDocument extends ControlRunbookDocument {
  standardLongName: string;
  standardVersion: string;
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const allowAnyRegex = String.raw`.*`;
    const docInputs: Input[] = [
      Input.ofTypeString('LogGroupName', {
        description: 'The name of the Log group to be used to create filters and metric alarms',
        defaultValue: `{{ssm:/Solutions/${props.solutionId}/Metrics_LogGroupName}}`,
        allowedPattern: allowAnyRegex,
      }),
      Input.ofTypeString('MetricNamespace', {
        description: 'The name of the metric namespace where the metrics will be logged',
        defaultValue: 'LogMetrics',
        allowedPattern: allowAnyRegex,
      }),
      Input.ofTypeString('KMSKeyArn', {
        description: `The ARN of the KMS key created by ${props.solutionAcronym} for remediations`,
        defaultValue: `{{ssm:/Solutions/${props.solutionId}/CMK_REMEDIATION_ARN}}`,
        allowedPattern: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(?:(?:alias\/[A-Za-z0-9/-_])|(?:key\/(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})))$`,
      }),
    ];

    const snsTopicName = getSNSTopicName(props.solutionId, props.solutionAcronym);

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'CloudWatch.1',
      remediationName: 'CreateLogMetricFilterAndAlarm',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of(
        `Added metric filter to the log group and notifications to SNS topic ${snsTopicName}.`,
      ),
    });
    this.standardLongName = props.standardLongName;
    this.standardVersion = props.standardVersion;
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      outputType: DataTypeEnum.STRING,
      name: 'ControlId',
      selector: '$.Payload.control_id',
    });

    return outputs;
  }

  protected override getExtraSteps(): AutomationStep[] {
    const getMetricFilterAndAlarmInputValueStep = new ExecuteScriptStep(this, 'GetMetricFilterAndAlarmInputValue', {
      language: ScriptLanguage.fromRuntime(this.runtimePython.name, 'verify'),
      code: ScriptCode.fromFile(
        fs.realpathSync(path.join(__dirname, '..', '..', 'common', 'cloudwatch_get_input_values.py')),
      ),
      inputPayload: {
        ControlId: StringVariable.of('ParseInput.ControlId'),
        StandardLongName: HardCodedString.of(this.standardLongName),
        StandardVersion: HardCodedString.of(this.standardVersion),
      },
      outputs: [
        {
          name: 'FilterName',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.filter_name',
        },
        {
          name: 'FilterPattern',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.filter_pattern',
        },
        {
          name: 'MetricName',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.metric_name',
        },
        {
          name: 'MetricValue',
          outputType: DataTypeEnum.INTEGER,
          selector: '$.Payload.metric_value',
        },
        {
          name: 'AlarmName',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.alarm_name',
        },
        {
          name: 'AlarmDesc',
          outputType: DataTypeEnum.STRING,
          selector: '$.Payload.alarm_desc',
        },
        {
          name: 'AlarmThreshold',
          outputType: DataTypeEnum.INTEGER,
          selector: '$.Payload.alarm_threshold',
        },
      ],
    });

    return [getMetricFilterAndAlarmInputValueStep];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.FilterName = StringVariable.of('GetMetricFilterAndAlarmInputValue.FilterName');
    params.FilterPattern = StringVariable.of('GetMetricFilterAndAlarmInputValue.FilterPattern');
    params.MetricName = StringVariable.of('GetMetricFilterAndAlarmInputValue.MetricName');
    params.MetricValue = StringVariable.of('GetMetricFilterAndAlarmInputValue.MetricValue');
    params.MetricNamespace = StringVariable.of('MetricNamespace');
    params.AlarmName = StringVariable.of('GetMetricFilterAndAlarmInputValue.AlarmName');
    params.AlarmDesc = StringVariable.of('GetMetricFilterAndAlarmInputValue.AlarmDesc');
    params.AlarmThreshold = StringVariable.of('GetMetricFilterAndAlarmInputValue.AlarmThreshold');
    params.LogGroupName = StringVariable.of('LogGroupName');
    params.SNSTopicName = getSNSTopicName(this.solutionId, 'SHARR');
    params.KMSKeyArn = StringVariable.of('KMSKeyArn');

    return params;
  }
}

function getSNSTopicName(solutionId: string, solutionAcronym: string) {
  return `${solutionId}-${solutionAcronym}-LocalAlarmNotification`;
}
