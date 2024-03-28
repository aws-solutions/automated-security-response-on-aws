// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CfnParameter, Duration, Fn } from 'aws-cdk-lib';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import setCondition from './cdk-helper/set-condition';
import {
  ComparisonOperator,
  Dashboard,
  GraphWidget,
  MathExpression,
  Metric,
  TextWidget,
  TreatMissingData,
  Unit,
} from 'aws-cdk-lib/aws-cloudwatch';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { Key } from 'aws-cdk-lib/aws-kms';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import { ServicePrincipal } from 'aws-cdk-lib/aws-iam';

export interface CloudWatchMetricsProps {
  solutionId: string;
  schedulingQueueName: string;
  orchStateMachineArn: string;
  kmsKey: Key;
}

export class CloudWatchMetrics {
  private readonly parameters: CfnParameter[] = [];
  private useCloudWatchMetrics: CfnParameter;

  constructor(scope: Construct, props: CloudWatchMetricsProps) {
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name

    props.kmsKey.grantEncryptDecrypt(new ServicePrincipal('cloudwatch.amazonaws.com'));

    /// CloudWatch Metrics
    this.useCloudWatchMetrics = new CfnParameter(scope, 'UseCloudWatchMetrics', {
      type: 'String',
      description:
        'Enable collection of operational metrics and create a CloudWatch dashboard to monitor solution operations',
      default: 'yes',
      allowedValues: ['yes', 'no'],
    });
    this.parameters.push(this.useCloudWatchMetrics);

    const isUsingCloudWatchMetrics = new CfnCondition(scope, 'isUsingCloudWatchMetrics', {
      expression: Fn.conditionEquals(this.useCloudWatchMetrics, 'yes'),
    });

    const useCloudWatchMetricsAlarms = new CfnParameter(scope, 'UseCloudWatchMetricsAlarms', {
      type: 'String',
      description: 'Create CloudWatch Alarms for gathered metrics',
      default: 'yes',
      allowedValues: ['yes', 'no'],
    });
    this.parameters.push(useCloudWatchMetricsAlarms);

    const isUsingCloudWatchMetricsAlarms = new CfnCondition(scope, 'isUsingCloudWatchMetricsAlarms', {
      expression: Fn.conditionAnd(isUsingCloudWatchMetrics, Fn.conditionEquals(useCloudWatchMetricsAlarms, 'yes')),
    });

    const stateMachineExecutionsAlarmThreshold = new CfnParameter(scope, 'StateMachineExecutionsAlarmThreshold', {
      type: 'Number',
      description: 'Number of executions in one period to trigger the state machine executions alarm',
      default: 1000,
    });
    this.parameters.push(stateMachineExecutionsAlarmThreshold);

    const sendCloudwatchMetricsParameter = new StringParameter(scope, 'ASR_SendCloudWatchMetrics', {
      description: 'Flag to enable or disable sending cloudwatch metrics.',
      parameterName: '/Solutions/' + RESOURCE_PREFIX + '/sendCloudwatchMetrics',
      stringValue: 'yes',
    });
    setCondition(sendCloudwatchMetricsParameter, isUsingCloudWatchMetrics);

    const defaultDuration = Duration.days(1);

    const lambdaErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'LAMBDAERROR' },
      label: 'LAMBDAERROR',
    });

    const remediationNotActiveErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'REMEDIATIONNOTTACTIVE' },
      label: 'REMEDIATIONNOTTACTIVE',
    });

    const noRemediationErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'NOREMEDIATION' },
      label: 'NOREMEDIATION',
    });

    const standardNotEnabledErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'STANDARDNOTENABLED' },
      label: 'STANDARDNOTENABLED',
    });

    const successMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'SUCCESS' },
      label: 'SUCCESS',
    });

    const waitTimeMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationSchedulingDelay',
      statistic: 'Maximum',
      unit: Unit.SECONDS,
      period: defaultDuration,
      label: 'Delay',
    });

    const failedExpression = new MathExpression({
      label: 'FAILURE',
      period: defaultDuration,
      expression: 'SUM([m1+m2+m3+m4])',
      usingMetrics: {
        ['m1']: lambdaErrorMetric,
        ['m2']: remediationNotActiveErrorMetric,
        ['m3']: noRemediationErrorMetric,
        ['m4']: standardNotEnabledErrorMetric,
      },
    });

    const failedAssumeRoleMetric = new Metric({
      namespace: 'ASR',
      metricName: 'AssumeRoleFailure',
      statistic: 'Sum',
      period: defaultDuration,
      label: 'Runbook Assume Role Failures',
    });

    const queueLengthMetric = new Metric({
      namespace: 'AWS/SQS',
      metricName: 'ApproximateNumberOfMessagesVisible',
      statistic: 'Maximum',
      period: defaultDuration,
      label: 'Queue Length',
      dimensionsMap: {
        QueueName: props.schedulingQueueName,
      },
    });

    const stateMachineExecutionsMetric = new Metric({
      namespace: 'AWS/States',
      metricName: 'ExecutionsStarted',
      statistic: 'Sum',
      period: defaultDuration,
      label: 'Remediations started',
      dimensionsMap: {
        StateMachineArn: props.orchStateMachineArn,
      },
    });

    /// CloudWatch Alarms
    const snsAlarmTopic = new Topic(scope, 'ASR-Alarm-Topic', {
      displayName: 'ASR Alarm Topic (' + RESOURCE_PREFIX + ')',
      topicName: RESOURCE_PREFIX + '-ASR_Alarm_Topic',
      masterKey: props.kmsKey,
    });
    setCondition(snsAlarmTopic, isUsingCloudWatchMetricsAlarms);

    const noRemediationErrorAlarm = noRemediationErrorMetric.createAlarm(scope, 'NoRemediationErrorAlarm', {
      alarmName: 'ASR-NoRemediation',
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Remediation failed with NOREMEDIATION result. This indicates a remediation was attempted for an unsupported remediation',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(noRemediationErrorAlarm, isUsingCloudWatchMetricsAlarms);
    noRemediationErrorAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));

    const failedAssumeRoleAlarm = failedAssumeRoleMetric.createAlarm(scope, 'FailedAssumeRoleAlarm', {
      alarmName: 'ASR-RunbookAssumeRoleFailure',
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'ASR Runbook Failed to assume role in an account. This indicates that a remediation was attempted in an account that does not have ASR deployed.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(failedAssumeRoleAlarm, isUsingCloudWatchMetricsAlarms);
    failedAssumeRoleAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));

    const stateMachineExecutionsAlarm = stateMachineExecutionsMetric.createAlarm(scope, 'StateMachineExecutions', {
      alarmName: 'ASR-StateMachineExecutions',
      evaluationPeriods: 1,
      threshold: stateMachineExecutionsAlarmThreshold.valueAsNumber,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: 'Number of executed remediations is higher than normal. Check other metrics.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
    });

    setCondition(stateMachineExecutionsAlarm, isUsingCloudWatchMetricsAlarms);
    stateMachineExecutionsAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));

    /// CloudWatch Dashboard
    const remediationDashboard = new Dashboard(scope, 'RemediationDashboard', {
      dashboardName: 'ASR-Remediation-Metrics-Dashboard',
      defaultInterval: Duration.days(7),
    });
    setCondition(remediationDashboard, isUsingCloudWatchMetrics);

    remediationDashboard.addWidgets(
      new GraphWidget({
        title: 'State Machine Executions',
        left: [stateMachineExecutionsMetric],
        leftAnnotations: [stateMachineExecutionsAlarm.toAnnotation()],
      }),
      new GraphWidget({
        title: 'Remediation Outcomes',
        left: [failedExpression, successMetric],
        leftYAxis: {
          showUnits: false,
        },
      }),
      new GraphWidget({
        title: 'Remediation Failures by Type',
        left: [
          lambdaErrorMetric,
          remediationNotActiveErrorMetric,
          noRemediationErrorMetric,
          standardNotEnabledErrorMetric,
        ],
        leftAnnotations: [noRemediationErrorAlarm.toAnnotation()],
        leftYAxis: {
          showUnits: false,
        },
      }),
      new TextWidget({
        markdown: `
## Remediation Failures by Type
This widget displays the frequency of different remediation outcomes.

If there is an increase in \`NOREMEDIATION\` results, this indicates that remediations are being attempted for remediations not currently included in ASR. You should verify that this is not caused by a modified automatic remediation rule.
`,
        height: 6,
      }),
    );

    remediationDashboard.addWidgets(
      new GraphWidget({
        title: 'Remediation Scheduling Queue Length',
        left: [queueLengthMetric],
      }),
      new GraphWidget({
        title: 'Maximum Remediation Delay',
        left: [waitTimeMetric],
      }),
      new TextWidget({
        markdown: `
## Remediation Scheduling Widgets
These widgets are related to scheduling of remediations.

Triggered remediations are inserted into a queue and a scheduling Lambda picks them up to schedule the remediation execution.

The queue length represents the maximum number of triggered remediations that were waiting to be scheduled during that period.

The maximum delay is how far out, in seconds, that the scheduling Lambda has scheduled a remediation for execution.
`,
        height: 6,
      }),
    );

    remediationDashboard.addWidgets(
      new GraphWidget({
        title: 'Runbook Assume Role Failures',
        left: [failedAssumeRoleMetric],
        leftAnnotations: [failedAssumeRoleAlarm.toAnnotation()],
        leftYAxis: {
          showUnits: false,
        },
      }),
      new TextWidget({
        markdown: `
## Runbook Assume Role Failures
This widget displays the frequency of the remediation lambda failing to assume the role necessary to remediate on a different account.

This may indicate that ASR is attempting to remediate on a spoke account that does not have ASR installed.
`,
        height: 6,
      }),
    );
  }

  public getParameterIds(): string[] {
    return this.parameters.map((p) => p.logicalId);
  }

  public getParameterIdsAndLabels() {
    return this.parameters.reduce((a, p) => ({ ...a, [p.logicalId]: { default: p.logicalId } }), {});
  }

  public getCloudWatchMetricsParameterValue(): string {
    return this.useCloudWatchMetrics.valueAsString;
  }
}
