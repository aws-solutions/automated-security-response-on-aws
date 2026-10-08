// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnCondition, CfnParameter, Duration, Fn } from 'aws-cdk-lib';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import setCondition from './cdk-helper/set-condition';
import {
  Color,
  ComparisonOperator,
  Dashboard,
  GraphWidget,
  GraphWidgetView,
  IMetric,
  LogQueryWidget,
  MathExpression,
  Metric,
  SingleValueWidget,
  TextWidget,
  TreatMissingData,
  Alarm,
} from 'aws-cdk-lib/aws-cloudwatch';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { Key } from 'aws-cdk-lib/aws-kms';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import { ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { SC_REMEDIATIONS } from '../playbooks/SC/lib/sc_remediations';
import { IControl } from './playbook-construct';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { getConfig, stripDevelopmentPrefix } from './config/cdk-config';
import {
  ASR_METRIC_NAMESPACE,
  CONTROL_STATE_CHANGE_METRIC,
  M2M_FORBIDDEN_AUTHORIZATION_METRIC,
  MCP_TOOL_ERROR_METRIC,
  SENSITIVE_WRITE_METRIC,
  USER_POOL_DIMENSION,
  WRITE_CATEGORY_DIMENSION,
} from '../lambdas/common/utils/cloudWatchMetrics';
import { RateLimitTierName } from '../lambdas/api/rateLimiting/routeTiers';

export interface CloudWatchMetricsProps {
  solutionId: string;
  schedulingQueueName: string;
  orchStateMachineArn: string;
  kmsKey: Key;
  actionLogLogGroupName: string;
  enhancedMetricsEnabled: CfnCondition;
  webUIEnabled: CfnCondition;
  /**
   * The EnableMcpServer=yes condition (agentCoreGatewayEnabled). The MCP server
   * Lambda that emits the McpTool* metrics only exists when it is true, so the
   * MCP alarm is gated on it.
   */
  mcpEnabled: CfnCondition;
  userPoolId?: string;
  preProcessorDLQName: string;
  notificationDLQName: string;
  schedulingDLQName: string;
  synchronizationLambdaName?: string;
  enableRollback: string;
}

interface DLQAlarmConfig {
  readonly queueName: string;
  readonly alarmName: string;
  readonly metricLabel: string;
  readonly alarmDescription: string;
}

export class CloudWatchMetrics {
  private readonly standardMetricParameters: CfnParameter[] = [];
  private readonly enhancedMetricParameters: CfnParameter[] = [];
  private readonly useCloudWatchMetrics: CfnParameter;
  private readonly isUsingCloudWatchMetrics: CfnCondition;
  private readonly isUsingCloudWatchMetricsAlarms: CfnCondition;
  private readonly enhancedMetricsEnabled: CfnCondition;
  private readonly enhancedAlarmsEnabled: CfnCondition;
  /**
   * Operational alarm topic. Callers can route additional alerts (e.g. S3
   * event notifications) to the same subscriber set that already receives
   * remediation alarms. Dependents on this topic must also gate themselves
   * on `alarmTopicCondition`; otherwise their resources will dangle when the
   * customer disables alarms via `UseCloudWatchMetricsAlarms`.
   */
  public readonly alarmTopic: Topic;
  /**
   * Condition under which `alarmTopic` is provisioned. Dependents on the
   * topic must mirror this condition on their own resources.
   */
  public readonly alarmTopicCondition: CfnCondition;

  constructor(scope: Construct, props: CloudWatchMetricsProps) {
    const RESOURCE_PREFIX = stripDevelopmentPrefix(props.solutionId); // prefix on every resource name

    props.kmsKey.grantEncryptDecrypt(new ServicePrincipal('cloudwatch.amazonaws.com'));

    /// CloudWatch Metrics
    this.useCloudWatchMetrics = new CfnParameter(scope, 'UseCloudWatchMetrics', {
      type: 'String',
      description:
        'Enable collection of operational metrics and create a CloudWatch dashboard to monitor solution operations',
      default: 'yes',
      allowedValues: ['yes', 'no'],
    });
    this.standardMetricParameters.push(this.useCloudWatchMetrics);

    this.isUsingCloudWatchMetrics = new CfnCondition(scope, 'isUsingCloudWatchMetrics', {
      expression: Fn.conditionEquals(this.useCloudWatchMetrics, 'yes'),
    });

    const useCloudWatchMetricsAlarms = new CfnParameter(scope, 'UseCloudWatchMetricsAlarms', {
      type: 'String',
      description: 'Create CloudWatch Alarms for gathered metrics',
      default: 'yes',
      allowedValues: ['yes', 'no'],
    });
    this.standardMetricParameters.push(useCloudWatchMetricsAlarms);

    this.isUsingCloudWatchMetricsAlarms = new CfnCondition(scope, 'isUsingCloudWatchMetricsAlarms', {
      expression: Fn.conditionAnd(this.isUsingCloudWatchMetrics, Fn.conditionEquals(useCloudWatchMetricsAlarms, 'yes')),
    });

    this.enhancedMetricsEnabled = props.enhancedMetricsEnabled;
    this.enhancedAlarmsEnabled = new CfnCondition(scope, 'enhancedAlarmsEnabled', {
      expression: Fn.conditionAnd(this.enhancedMetricsEnabled, this.isUsingCloudWatchMetricsAlarms),
    });

    const remediationFailureAlarmThreshold = new CfnParameter(scope, 'RemediationFailureAlarmThreshold', {
      type: 'Number',
      description:
        'Percentage of failures in one period (1 day) to trigger the remediation failures alarm for a given control ID. E.g., to specify 20% then enter the number 20. These alarms will not be created if you select "no" for either of the following standardMetricParameters: UseCloudWatchMetricsAlarms, EnableEnhancedCloudWatchMetrics.',
      default: 5,
    });
    this.enhancedMetricParameters.push(remediationFailureAlarmThreshold);

    const rollbackRateLimitThreshold = new CfnParameter(scope, 'RollbackRateLimitThreshold', {
      type: 'Number',
      description:
        'Number of rollback executions in one period (1 day) to trigger the rollback rate-limit alarm. E.g., to alarm on 10 or more rollbacks per day, enter 10.',
      default: 10,
    });
    this.standardMetricParameters.push(rollbackRateLimitThreshold);

    const sendCloudwatchMetricsParameter = new StringParameter(scope, 'ASR_SendCloudWatchMetrics', {
      description: 'Flag to enable or disable sending cloudwatch metrics.',
      parameterName: '/Solutions/' + RESOURCE_PREFIX + '/sendCloudwatchMetrics',
      stringValue: 'yes',
    });
    setCondition(sendCloudwatchMetricsParameter, this.isUsingCloudWatchMetrics);

    const defaultDuration = Duration.days(1);

    const lambdaErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'LAMBDA_ERROR' },
      label: 'Lambda Error',
    });

    const remediationNotActiveErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'RUNBOOK_NOT_ACTIVE' },
      label: 'Runbook Not Active',
    });

    const noRemediationErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'NO_RUNBOOK' },
      label: 'No Remediation',
    });

    const playbookNotEnabledErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'PLAYBOOK_NOT_ENABLED' },
      label: 'Playbook Not Enabled',
    });

    const automationDocumentFailedMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'FAILED' },
      label: 'SSM Doc Failed',
    });

    const successMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: Duration.days(90), // 3 months
      dimensionsMap: { Outcome: 'SUCCESS' },
      label: 'Successful Remediations',
    });

    const hoursSavedMetric = new MathExpression({
      label: 'Estimated Hours Saved',
      period: defaultDuration,
      expression: '(m1 * 10) / 60',
      usingMetrics: {
        ['m1']: successMetric,
      },
    });

    const failuresByTypeExpression = new MathExpression({
      label: 'FAILURE',
      period: defaultDuration,
      expression: 'SUM([m1+m2+m3+m4+m5])',
      usingMetrics: {
        ['m1']: lambdaErrorMetric,
        ['m2']: remediationNotActiveErrorMetric,
        ['m3']: noRemediationErrorMetric,
        ['m4']: playbookNotEnabledErrorMetric,
        ['m5']: automationDocumentFailedMetric,
      },
    });

    const remediationFailureRateExpression = new MathExpression({
      label: 'Overall Failure Rate',
      period: defaultDuration,
      expression: '(failuresByType / (failuresByType + successMetric)) * 100',
      usingMetrics: {
        ['failuresByType']: failuresByTypeExpression,
        ['successMetric']: successMetric,
      },
    });

    const failedAssumeRoleMetric = new Metric({
      namespace: 'ASR',
      metricName: 'AssumeRoleFailure',
      statistic: 'Sum',
      period: defaultDuration,
      label: 'Runbook Assume Role Failures',
    });

    /// CloudWatch Alarms
    // alarmTopic is gated on isUsingCloudWatchMetricsAlarms because every
    // alarm publishing to it carries the same condition. Dependents on
    // alarmTopic must mirror this condition via alarmTopicCondition.
    const snsAlarmTopic = new Topic(scope, 'ASR-Alarm-Topic', {
      displayName: 'ASR Alarm Topic (' + RESOURCE_PREFIX + ')',
      topicName: RESOURCE_PREFIX + '-ASR_Alarm_Topic',
      masterKey: props.kmsKey,
    });
    setCondition(snsAlarmTopic, this.isUsingCloudWatchMetricsAlarms);
    this.alarmTopic = snsAlarmTopic;
    this.alarmTopicCondition = this.isUsingCloudWatchMetricsAlarms;

    const noRemediationErrorAlarm = noRemediationErrorMetric.createAlarm(scope, 'NoRemediationErrorAlarm', {
      alarmName: 'ASR-NoRunbook',
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Remediation failed with NO_RUNBOOK result. This indicates a remediation was attempted and an ASR runbook could not be found. This can happen if the member stack is not deployed in the account & region where the finding was generated, or ASR does not support the control ID.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(noRemediationErrorAlarm, this.isUsingCloudWatchMetricsAlarms);
    noRemediationErrorAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(noRemediationErrorAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

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
    setCondition(failedAssumeRoleAlarm, this.isUsingCloudWatchMetricsAlarms);
    failedAssumeRoleAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(failedAssumeRoleAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // DLQ monitoring: alarm whenever a message is redriven to one of the SQS-backed
    // pipelines' dead-letter queues, which means retries were exhausted and the message
    // would otherwise be lost silently.
    this.createDLQAlarm(
      scope,
      'PreProcessorDLQAlarm',
      {
        queueName: props.preProcessorDLQName,
        alarmName: 'ASR-PreProcessorDLQ',
        metricLabel: 'Automated Security Response on AWS: Pre-processor DLQ Messages',
        alarmDescription:
          'Automated Security Response on AWS: Messages have been sent to the Pre-processor Dead Letter Queue. This indicates that the Pre-processor Lambda function failed to process Security Hub findings after multiple retry attempts.',
      },
      snsAlarmTopic,
    );

    this.createDLQAlarm(
      scope,
      'NotificationDLQAlarm',
      {
        queueName: props.notificationDLQName,
        alarmName: 'ASR-NotificationDLQ',
        metricLabel: 'Automated Security Response on AWS: Notification dispatcher DLQ Messages',
        alarmDescription:
          'Automated Security Response on AWS: Messages have been sent to the notification dispatcher Dead Letter Queue. This indicates that the notification dispatcher Lambda function failed to deliver notification events after multiple retry attempts.',
      },
      snsAlarmTopic,
    );

    this.createDLQAlarm(
      scope,
      'SchedulingDLQAlarm',
      {
        queueName: props.schedulingDLQName,
        alarmName: 'ASR-SchedulingDLQ',
        metricLabel: 'Automated Security Response on AWS: Scheduling DLQ Messages',
        alarmDescription:
          'Automated Security Response on AWS: Messages have been sent to the remediation scheduling Dead Letter Queue. This indicates that scheduled remediations failed to reach the Orchestrator after multiple retry attempts.',
      },
      snsAlarmTopic,
    );

    if (props.synchronizationLambdaName) {
      const synchronizationErrorMetric = new Metric({
        namespace: 'AWS/Lambda',
        metricName: 'Errors',
        statistic: 'Sum',
        period: Duration.minutes(5),
        dimensionsMap: { FunctionName: props.synchronizationLambdaName },
        label: 'Synchronization Lambda Errors',
      });

      const synchronizationErrorAlarm = synchronizationErrorMetric.createAlarm(scope, 'SynchronizationErrorAlarm', {
        alarmName: 'ASR-SynchronizationError',
        evaluationPeriods: 1,
        threshold: 1,
        comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        alarmDescription:
          "Automated Security Response on AWS: The synchronization Lambda function has failed. This indicates that the synchronization process for Security Hub findings may not be working correctly and findings displayed in the UI may contain outdated information. Please see the function's log group for more information.",
        treatMissingData: TreatMissingData.NOT_BREACHING,
        datapointsToAlarm: 1,
        actionsEnabled: true,
      });
      setCondition(synchronizationErrorAlarm, this.isUsingCloudWatchMetricsAlarms);
      synchronizationErrorAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
      addCfnGuardSuppression(synchronizationErrorAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    }

    const rollbackAlarmEnabled = new CfnCondition(scope, 'rollbackAlarmEnabled', {
      expression: Fn.conditionAnd(this.isUsingCloudWatchMetricsAlarms, Fn.conditionEquals(props.enableRollback, 'yes')),
    });

    // Gate on rollback being enabled, wire to the alarm topic, and suppress the
    // explicit-name guard — the triplet every rollback alarm below needs.
    const finalizeRollbackAlarm = (alarm: Alarm): void => {
      setCondition(alarm, rollbackAlarmEnabled);
      alarm.addAlarmAction(new SnsAction(snsAlarmTopic));
      addCfnGuardSuppression(alarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    };

    const rollbackExecutionMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RollbackExecutionOutcome',
      statistic: 'Sum',
      period: Duration.days(1),
      dimensionsMap: { Outcome: 'Success' },
      label: 'Daily Rollback Executions',
    });

    const rollbackRateLimitAlarm = rollbackExecutionMetric.createAlarm(scope, 'RollbackRateLimitAlarm', {
      alarmName: 'ASR-RollbackRateLimit',
      evaluationPeriods: 1,
      threshold: rollbackRateLimitThreshold.valueAsNumber,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Automated Security Response on AWS: Unusual rollback activity detected. The daily rollback count exceeded the configured threshold, which may indicate unauthorized or automated rollback abuse.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    finalizeRollbackAlarm(rollbackRateLimitAlarm);

    const snapshotCaptureFailureAlarm = new Metric({
      namespace: 'ASR',
      metricName: 'SnapshotCaptureFailure',
      statistic: 'Sum',
      period: Duration.minutes(5),
      label: 'Snapshot Capture Failures',
    }).createAlarm(scope, 'SnapshotCaptureFailureAlarm', {
      alarmName: 'ASR-Rollback-SnapshotCaptureFailure',
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Automated Security Response on AWS: A pre-remediation snapshot capture failed, so the affected remediation is not rollback-capable. Remediation still proceeds (fail-open); this alarm surfaces the loss of rollback coverage.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    finalizeRollbackAlarm(snapshotCaptureFailureAlarm);

    const rollbackFailureRateAlarm = new MathExpression({
      expression:
        'IF((FILL(failed,0) + FILL(succeeded,0)) >= 3, ' +
        '100 * FILL(failed,0) / (FILL(failed,0) + FILL(succeeded,0)), 0)',
      usingMetrics: {
        failed: new Metric({
          namespace: 'ASR',
          metricName: 'RollbackExecutionOutcome',
          statistic: 'Sum',
          period: Duration.minutes(15),
          dimensionsMap: { Outcome: 'Failed' },
        }),
        succeeded: new Metric({
          namespace: 'ASR',
          metricName: 'RollbackExecutionOutcome',
          statistic: 'Sum',
          period: Duration.minutes(15),
          dimensionsMap: { Outcome: 'Success' },
        }),
      },
      period: Duration.minutes(15),
      label: 'Rollback failure rate (%)',
    }).createAlarm(scope, 'RollbackExecutionFailureAlarm', {
      alarmName: 'ASR-Rollback-ExecutionFailureRate',
      evaluationPeriods: 1,
      threshold: 20,
      comparisonOperator: ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription:
        'Automated Security Response on AWS: More than 20% of rollback executions failed over a 15-minute window. This can indicate a broken rollback path, missing member-account permissions, or snapshot drift.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    finalizeRollbackAlarm(rollbackFailureRateAlarm);

    // Deprecated controls keep their runbook SSM document but produce no findings,
    // so exclude them from per-control failure-rate alarms.
    const controlIds = SC_REMEDIATIONS.filter((remediation: IControl) => !remediation.deprecated).map(
      (remediation: IControl) => remediation.control,
    );
    const failureRateMetricsByControlId: IMetric[] = this.createAlarmsByControlId(
      scope,
      remediationFailureAlarmThreshold.valueAsNumber,
      snsAlarmTopic,
      defaultDuration,
      controlIds,
    );

    /// CloudWatch Dashboard
    const remediationDashboard = new Dashboard(scope, 'RemediationDashboard', {
      dashboardName: 'ASR-Remediation-Metrics-Dashboard',
      defaultInterval: Duration.days(7),
    });
    setCondition(remediationDashboard, this.isUsingCloudWatchMetrics);

    remediationDashboard.addWidgets(
      new TextWidget({
        markdown: `
## Total Successful Remediations
This widget displays the total number of successful remediations executed and total developer hours saved in the last 3 months.

We estimate that, on average, it takes 30 minutes of developer time to investigate & remediate a Security Hub finding. The "Estimated Hours Saved" widget uses this to estimate how many developer hours were saved by using ASR in the last 3 months.
`,
        height: 3,
        width: 24,
      }),
      new SingleValueWidget({
        title: 'Total Successful Remediations',
        metrics: [successMetric],
        setPeriodToTimeRange: true,
        height: 6,
      }),
      new SingleValueWidget({
        title: 'Estimated Hours Saved',
        metrics: [hoursSavedMetric],
        setPeriodToTimeRange: true,
        height: 6,
      }),
    );

    remediationDashboard.addWidgets(
      new TextWidget({
        markdown: `
## Remediation Failures by Type
This widget displays the frequency of various remediation failures. 
* \`Lambda Error\`: One or more of the solution's Lambda Functions failed to execute. See the Orchestrator step function execution for details.
* \`Runbook Not Active\`: The runbook associated with this remediation is not properly deployed in the solution's Admin and/or Member stack. Verify the solution's parameters.
* \`No Runbook\`: This indicates a remediation was attempted and an ASR runbook could not be found.
* \`Playbook Not Enabled\`: The ASR playbook associated with the finding is not enabled. Ensure that the correct playbook parameter is enabled in the Admin & Member stacks.
* \`SSM Doc Failed\`: The remediation script failed to execute. Check the Orchestrator step function to determine which account the remediation was executed in, then view the SSM automation execution history for failures.

If there is an increase in \`NO_RUNBOOK\` results, this indicates that (1) the account/region where findings are being generated does not have the member stack installed, or (2) ASR does not implement a remediation for the findings being executed. You should also verify that this is not caused by a malformed event pattern in the automatic remediation EventBridge rules.
`,
        height: 6,
        width: 24,
      }),
      new GraphWidget({
        title: 'Remediation Failures',
        left: [failuresByTypeExpression],
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
          playbookNotEnabledErrorMetric,
          automationDocumentFailedMetric,
        ],
        leftYAxis: {
          showUnits: false,
        },
      }),
      new GraphWidget({
        title: 'Remediation Failure Rate',
        left: [remediationFailureRateExpression],
        leftYAxis: {
          showUnits: false,
        },
      }),
    );
    remediationDashboard.addWidgets(
      new TextWidget({
        markdown: `
## Remediation Success/Failure by Control ID
This widget displays the number of successful and failed remediations by Control ID. You must select "Yes" for EnableEnhancedCloudWatchMetrics when deploying the Admin stack to view these metrics.

The number of failed remediations per Control ID can inform you of frequent issues that arise when ASR attempts to remediate a specific finding in your AWS environment. If a high number of failures occur on a small subset of controls, you can investigate the issue by navigating to \`Systems Manager > Automation\` to search for recent executions of the control runbook associated with the failing Control ID. 
`,
        height: 3,
        width: 24,
      }),
      new GraphWidget({
        title: 'Successful remediations by Control Id',
        left: [
          new MathExpression({
            expression: "SORT(SEARCH('{ASR,ControlId,Outcome} Outcome=\"SUCCESS\"', 'Sum'), SUM, ASC)",
            label: '',
            period: defaultDuration,
          }),
        ],
        view: GraphWidgetView.BAR,
        statistic: 'Sum',
      }),
      new GraphWidget({
        title: 'Failed remediations by Control Id',
        left: [
          new MathExpression({
            expression: "SORT(SEARCH('{ASR,ControlId,Outcome} Outcome=\"FAILED\"', 'Sum'), SUM, ASC)",
            label: '',
            period: defaultDuration,
          }),
        ],
        view: GraphWidgetView.BAR,
        statistic: 'Sum',
      }),
      new GraphWidget({
        title: 'Remediation Failure Rate by Control Id',
        left: failureRateMetricsByControlId,
        leftAnnotations: [
          {
            value: remediationFailureAlarmThreshold.valueAsNumber,
            label: `S3.9 Failure Percentage >= threshold for 1 datapoints within 1 day`,
            color: Color.RED,
            visible: true,
          },
        ],
        view: GraphWidgetView.TIME_SERIES,
      }),
    );

    remediationDashboard.addWidgets(
      new TextWidget({
        markdown: `
## Runbook Assume Role Failures
This widget displays the frequency of the remediation lambda failing to assume the role necessary to remediate on a different account.

This may indicate that ASR is attempting to remediate on a spoke account that does not have ASR installed.
`,
        height: 3,
        width: 24,
      }),
      new GraphWidget({
        title: 'Runbook Assume Role Failures',
        left: [failedAssumeRoleMetric],
        leftAnnotations: [failedAssumeRoleAlarm.toAnnotation()],
        leftYAxis: {
          showUnits: false,
        },
      }),
    );

    remediationDashboard.addWidgets(
      new TextWidget({
        markdown: `
## Action Log
This widget displays AWS resource changes that ASR has conducted in member accounts.

The actions shown are based on CloudTrail management events in the member accounts. Actions are only reported if the member stack is deployed with "Create Action Log CloudTrail" set to "Yes".
`,
        height: 3,
        width: 24,
      }),
      new LogQueryWidget({
        logGroupNames: [props.actionLogLogGroupName],
        queryLines: [
          'fields @timestamp, eventSource, eventName, awsRegion, recipientAccountId, resources.0.ARN, @message',
          'sort @timestamp desc',
          'limit 20',
        ],
        height: 8,
        width: 24,
        title: 'CloudTrail Management Actions by ASR',
      }),
    );

    const snapshotCaptureSearch = (metricName: string, label: string): MathExpression =>
      new MathExpression({
        expression: `SUM(SEARCH('{ASR,ControlId} MetricName="${metricName}"', 'Sum', 300))`,
        usingMetrics: {},
        label,
        period: Duration.minutes(5),
      });

    remediationDashboard.addWidgets(
      new TextWidget({
        markdown: `
## Rollback
Pre-remediation snapshot capture and one-click rollback execution activity. Populated only when rollback is enabled (EnableRollback=yes). The Snapshot Capture Outcomes widget sums the per-ControlId series, so it also requires EnableEnhancedCloudWatchMetrics=yes; without it only the aggregate SnapshotCaptureFailure alarm is populated.
`,
        height: 2,
        width: 24,
      }),
      new GraphWidget({
        title: 'Snapshot Capture Outcomes',
        left: [
          snapshotCaptureSearch('SnapshotCaptureSuccess', 'Captured'),
          snapshotCaptureSearch('SnapshotCaptureFailure', 'Failed'),
          snapshotCaptureSearch('SnapshotCaptureSkipped', 'Skipped (not eligible)'),
        ],
        height: 6,
        width: 12,
      }),
      new GraphWidget({
        title: 'Rollback Executions by Outcome',
        left: [
          new Metric({
            namespace: 'ASR',
            metricName: 'RollbackExecutionOutcome',
            statistic: 'Sum',
            period: Duration.minutes(5),
            dimensionsMap: { Outcome: 'Success' },
            label: 'Success',
          }),
          new Metric({
            namespace: 'ASR',
            metricName: 'RollbackExecutionOutcome',
            statistic: 'Sum',
            period: Duration.minutes(5),
            dimensionsMap: { Outcome: 'Failed' },
            label: 'Failed',
          }),
        ],
        height: 6,
        width: 12,
      }),
    );

    // Cognito Threat Protection Alarms
    if (props.userPoolId) {
      this.createCognitoThreatProtectionAlarms(scope, snsAlarmTopic, props.userPoolId, props.webUIEnabled);
    }

    // API rate-limiting and write-anomaly alarms (gated on the WebUI being
    // enabled, since the API Lambda that emits these metrics only exists then).
    this.createApiRateLimitAlarms(scope, snsAlarmTopic, props.webUIEnabled);

    // MCP server tool-error alarm (gated on EnableMcpServer=yes, since the MCP
    // server Lambda that emits McpToolError only exists then).
    this.createMcpServerAlarms(scope, snsAlarmTopic, props.mcpEnabled);
  }

  /**
   * Creates a CloudWatch alarm that fires when messages are present in a dead-letter
   * queue (the `ApproximateNumberOfMessagesVisible` SQS metric). All DLQ alarms share the
   * same threshold, missing-data handling, opt-in condition, and SNS action so they behave
   * consistently across the solution's SQS-backed pipelines.
   */
  private createDLQAlarm(scope: Construct, id: string, config: DLQAlarmConfig, snsAlarmTopic: Topic): void {
    const metric = new Metric({
      namespace: 'AWS/SQS',
      metricName: 'ApproximateNumberOfMessagesVisible',
      statistic: 'Maximum',
      period: Duration.minutes(1),
      dimensionsMap: { QueueName: config.queueName },
      label: config.metricLabel,
    });

    const alarm = metric.createAlarm(scope, id, {
      alarmName: config.alarmName,
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription: config.alarmDescription,
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(alarm, this.isUsingCloudWatchMetricsAlarms);
    alarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(alarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
  }

  private createAlarmsByControlId(
    scope: Construct,
    alarmThreshold: number,
    snsAlarmTopic: Topic,
    duration: Duration,
    controlIds: string[],
  ) {
    const metricsByControlId: IMetric[] = [];

    controlIds.forEach((controlId: string) => {
      const failuresByControlIdMetric = new Metric({
        namespace: 'ASR',
        metricName: 'RemediationOutcome',
        dimensionsMap: { Outcome: 'FAILED', ControlId: controlId },
        period: duration,
      });
      const successByControlIdMetric = new Metric({
        namespace: 'ASR',
        metricName: 'RemediationOutcome',
        dimensionsMap: { Outcome: 'SUCCESS', ControlId: controlId },
        period: duration,
      });

      const alphanumericControlId = controlId.replace(/\W/g, '');
      const failuresMetricName = `m1${alphanumericControlId}`;
      const successesMetricName = `m2${alphanumericControlId}`;
      const failurePercentage = new MathExpression({
        label: `${controlId} Failure Percentage`,
        period: duration,
        expression: `(${failuresMetricName} / (${failuresMetricName}+${successesMetricName})) * 100`,
        usingMetrics: {
          [failuresMetricName]: failuresByControlIdMetric,
          [successesMetricName]: successByControlIdMetric,
        },
      });
      metricsByControlId.push(failurePercentage);

      const remediationFailureAlarm = failurePercentage.createAlarm(scope, `${controlId}-remediation-failure`, {
        alarmName: `ASR-${controlId}-remediation-failure`,
        evaluationPeriods: 1,
        threshold: alarmThreshold,
        comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        alarmDescription: `This alarm triggers when the percentage of remediation failures for ${controlId} reaches above the configured threshold. 
        This indicates that there may be a problem remediating this control ID in your AWS environment. Check the most recent failed execution of this control's runbook in the target account to identify potential issues.`,
        treatMissingData: TreatMissingData.NOT_BREACHING,
        datapointsToAlarm: 1,
      });

      setCondition(remediationFailureAlarm, this.enhancedAlarmsEnabled);
      remediationFailureAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));

      addCfnGuardSuppression(remediationFailureAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    });

    return metricsByControlId;
  }

  private getParameterIds(parameters: CfnParameter[]): string[] {
    return parameters.map((param) => param.logicalId);
  }

  public getStandardParameterIds(): string[] {
    return this.getParameterIds(this.standardMetricParameters);
  }

  public getEnhancedParameterIds(): string[] {
    return this.getParameterIds(this.enhancedMetricParameters);
  }

  private createCognitoThreatProtectionAlarms(
    scope: Construct,
    snsAlarmTopic: Topic,
    userPoolId: string,
    webUIEnabled: CfnCondition,
  ) {
    const cognitoAlarmsCondition = new CfnCondition(scope, 'cognitoAlarmsEnabled', {
      expression: Fn.conditionAnd(this.isUsingCloudWatchMetricsAlarms, webUIEnabled),
    });

    const riskMetric = new Metric({
      namespace: 'AWS/Cognito',
      metricName: 'Risk',
      statistic: 'Sum',
      period: Duration.minutes(1),
      dimensionsMap: { UserPool: userPoolId },
    });

    const riskAlarm = riskMetric.createAlarm(scope, 'CognitoRiskAlarm', {
      alarmName: 'ASR-Cognito-Risk',
      evaluationPeriods: 5,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Alarm for the Automated Security Response on AWS Cognito User Pool: Requests that Amazon Cognito marked as risky',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(riskAlarm, cognitoAlarmsCondition);
    riskAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(riskAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    const overrideBlockMetric = new Metric({
      namespace: 'AWS/Cognito',
      metricName: 'OverrideBlock',
      statistic: 'Sum',
      period: Duration.minutes(1),
      dimensionsMap: { UserPool: userPoolId },
    });

    const overrideBlockAlarm = overrideBlockMetric.createAlarm(scope, 'CognitoOverrideBlockAlarm', {
      alarmName: 'ASR-Cognito-OverrideBlock',
      evaluationPeriods: 5,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Alarm for the Automated Security Response on AWS Cognito User Pool: Requests that Amazon Cognito blocked because of the configuration provided by the developer',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 5,
      actionsEnabled: true,
    });
    setCondition(overrideBlockAlarm, cognitoAlarmsCondition);
    overrideBlockAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(overrideBlockAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    const signInThrottlesMetric = new Metric({
      namespace: 'AWS/Cognito',
      metricName: 'SignInThrottles',
      statistic: 'Sum',
      period: Duration.minutes(1),
      dimensionsMap: { UserPool: userPoolId },
    });

    const signInThrottlesAlarm = signInThrottlesMetric.createAlarm(scope, 'CognitoSignInThrottlesAlarm', {
      alarmName: 'ASR-Cognito-SignInThrottles',
      evaluationPeriods: 5,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Alarm for the Automated Security Response on AWS Cognito User Pool: Total number of throttled user authentication requests made to the Amazon Cognito user pool',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 5,
      actionsEnabled: true,
    });
    setCondition(signInThrottlesAlarm, cognitoAlarmsCondition);
    signInThrottlesAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(signInThrottlesAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    // M2M (machine-to-machine) Full Access denial alarm. Fires when a groupless
    // M2M access token is denied Full Access for lacking the `asr-api/full-access`
    // scope. A non-zero count signals a misconfigured M2M client or probing against
    // the API. Watches the custom ASR/M2MForbiddenAuthorization metric the API
    // Lambda emits on each denial (same name + UserPool dimension constants); treats
    // missing data as NOT_BREACHING so it stays silent until denials occur.
    const m2mForbiddenMetric = new Metric({
      namespace: ASR_METRIC_NAMESPACE,
      metricName: M2M_FORBIDDEN_AUTHORIZATION_METRIC,
      statistic: 'Sum',
      period: Duration.minutes(1),
      dimensionsMap: { [USER_POOL_DIMENSION]: userPoolId },
    });

    const m2mForbiddenAlarm = m2mForbiddenMetric.createAlarm(scope, 'CognitoM2MForbiddenAlarm', {
      alarmName: 'ASR-Cognito-M2MForbidden',
      evaluationPeriods: 5,
      threshold: 1,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Alarm for the Automated Security Response on AWS Cognito User Pool: a machine-to-machine (M2M) token was denied Full Access for lacking the asr-api/full-access scope. A non-zero count indicates a misconfigured M2M client or probing against the API.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(m2mForbiddenAlarm, cognitoAlarmsCondition);
    m2mForbiddenAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(m2mForbiddenAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
  }

  /**
   * Alarms on anomalous API write activity and rate-limit rejections, using the
   * custom `ASR`-namespace metrics emitted by the API Lambda. Gated on the
   * WebUI being enabled because the API only exists in that case. Thresholds are
   * sourced from the rate-limiting config.
   */
  private createApiRateLimitAlarms(scope: Construct, snsAlarmTopic: Topic, webUIEnabled: CfnCondition): void {
    const alarmsConfig = getConfig().rateLimiting.alarms;
    const period = Duration.minutes(1);

    const apiAlarmsCondition = new CfnCondition(scope, 'apiRateLimitAlarmsEnabled', {
      expression: Fn.conditionAnd(this.isUsingCloudWatchMetricsAlarms, webUIEnabled),
    });

    const finalizeAlarm = (alarm: Alarm): void => {
      setCondition(alarm, apiAlarmsCondition);
      alarm.addAlarmAction(new SnsAction(snsAlarmTopic));
      addCfnGuardSuppression(alarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
    };

    // Tier category dimension values, typed against the canonical tier union so
    // they cannot drift from the route tiers the Lambda emits them under.
    const criticalCategory: RateLimitTierName = 'critical';
    const sensitiveWriteCategory: RateLimitTierName = 'sensitiveWrite';

    // Anomalous volume of control state-change (bulk-edit) requests. This is the
    // security finding's explicit ask. Counts requests, not controls, so a
    // legitimate bulk operation over many controls registers as a single change.
    const controlStateChangeAlarm = new Metric({
      namespace: ASR_METRIC_NAMESPACE,
      metricName: CONTROL_STATE_CHANGE_METRIC,
      statistic: 'Sum',
      period,
    }).createAlarm(scope, 'ApiControlStateChangeAlarm', {
      alarmName: 'ASR-Api-ControlStateChangeSpike',
      evaluationPeriods: 1,
      threshold: alarmsConfig.controlStateChangesPerMinute,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Automated Security Response on AWS: An unusually high number of control state-change (bulk-edit) requests occurred within one minute. This can indicate a compromised credential rapidly enabling or disabling automated remediation controls.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    finalizeAlarm(controlStateChangeAlarm);

    // Spike in sensitive write requests across the critical and sensitive tiers
    // (user, filter, notification, and finding-action mutations). FILL(...,0)
    // keeps the sum well-defined when a category has no data in the period.
    const sensitiveWriteAlarm = new MathExpression({
      label: 'Sensitive write requests',
      period,
      expression: 'SUM([FILL(critical,0),FILL(sensitive,0)])',
      usingMetrics: {
        critical: new Metric({
          namespace: ASR_METRIC_NAMESPACE,
          metricName: SENSITIVE_WRITE_METRIC,
          statistic: 'Sum',
          period,
          dimensionsMap: { [WRITE_CATEGORY_DIMENSION]: criticalCategory },
        }),
        sensitive: new Metric({
          namespace: ASR_METRIC_NAMESPACE,
          metricName: SENSITIVE_WRITE_METRIC,
          statistic: 'Sum',
          period,
          dimensionsMap: { [WRITE_CATEGORY_DIMENSION]: sensitiveWriteCategory },
        }),
      },
    }).createAlarm(scope, 'ApiSensitiveWriteAlarm', {
      alarmName: 'ASR-Api-SensitiveWriteSpike',
      evaluationPeriods: 1,
      threshold: alarmsConfig.sensitiveWritesPerMinute,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        'Automated Security Response on AWS: An unusually high number of sensitive write requests (user, filter, notification, or finding-action changes) occurred within one minute.',
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    finalizeAlarm(sensitiveWriteAlarm);
  }

  /**
   * Alarm on a spike in MCP tool errors (5xx tool failures). Watches the
   * dimensionless McpToolError total emitted alongside the per-ToolName series
   * so a single alarm covers every tool; CloudWatch alarms cannot roll up a
   * dimension with SEARCH. Gated on EnableMcpServer=yes because the MCP server
   * Lambda that emits McpToolError only exists then.
   */
  private createMcpServerAlarms(scope: Construct, snsAlarmTopic: Topic, mcpEnabled: CfnCondition): void {
    const mcpAlarmsCondition = new CfnCondition(scope, 'mcpServerAlarmsEnabled', {
      expression: Fn.conditionAnd(this.isUsingCloudWatchMetricsAlarms, mcpEnabled),
    });

    const toolErrorAlarm = new Metric({
      namespace: ASR_METRIC_NAMESPACE,
      metricName: MCP_TOOL_ERROR_METRIC,
      statistic: 'Sum',
      period: Duration.minutes(5),
    }).createAlarm(scope, 'McpToolErrorAlarm', {
      alarmName: 'ASR-Mcp-ToolErrorSpike',
      evaluationPeriods: 1,
      threshold: 5,
      comparisonOperator: ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      alarmDescription:
        "Automated Security Response on AWS: An unusually high number of MCP tool invocations failed with server errors within five minutes. This can indicate a misbehaving MCP client, a broken tool, an attempt to probe the MCP server, or a transient dependency failure (for example, being unable to read the Cognito signing keys or the caller's authorization data).",
      treatMissingData: TreatMissingData.NOT_BREACHING,
      datapointsToAlarm: 1,
      actionsEnabled: true,
    });
    setCondition(toolErrorAlarm, mcpAlarmsCondition);
    toolErrorAlarm.addAlarmAction(new SnsAction(snsAlarmTopic));
    addCfnGuardSuppression(toolErrorAlarm, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');
  }
}
