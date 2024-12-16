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
} from 'aws-cdk-lib/aws-cloudwatch';
import { Topic } from 'aws-cdk-lib/aws-sns';
import { Key } from 'aws-cdk-lib/aws-kms';
import { SnsAction } from 'aws-cdk-lib/aws-cloudwatch-actions';
import { ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { SC_REMEDIATIONS } from '../playbooks/SC/lib/sc_remediations';
import { IControl } from './sharrplaybook-construct';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-nag-suppression';

export interface CloudWatchMetricsProps {
  solutionId: string;
  schedulingQueueName: string;
  orchStateMachineArn: string;
  kmsKey: Key;
  actionLogLogGroupName: string;
  enhancedMetricsEnabled: CfnCondition;
}

export class CloudWatchMetrics {
  private readonly parameters: CfnParameter[] = [];
  private readonly useCloudWatchMetrics: CfnParameter;
  private readonly isUsingCloudWatchMetrics: CfnCondition;
  private readonly isUsingCloudWatchMetricsAlarms: CfnCondition;
  private readonly enhancedMetricsEnabled: CfnCondition;
  private readonly enhancedAlarmsEnabled: CfnCondition;

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

    this.isUsingCloudWatchMetrics = new CfnCondition(scope, 'isUsingCloudWatchMetrics', {
      expression: Fn.conditionEquals(this.useCloudWatchMetrics, 'yes'),
    });

    const useCloudWatchMetricsAlarms = new CfnParameter(scope, 'UseCloudWatchMetricsAlarms', {
      type: 'String',
      description: 'Create CloudWatch Alarms for gathered metrics',
      default: 'yes',
      allowedValues: ['yes', 'no'],
    });
    this.parameters.push(useCloudWatchMetricsAlarms);

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
        'Percentage of failures in one period (1 day) to trigger the remediation failures alarm for a given control ID. E.g., to specify 20% then enter the number 20. These alarms will not be created if you select "no" on either of the following parameters: UseCloudWatchMetricsAlarms, EnableEnhancedCloudWatchMetrics.',
      default: 5,
    });
    this.parameters.push(remediationFailureAlarmThreshold);

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
      dimensionsMap: { Outcome: 'LAMBDAERROR' },
      label: 'Lambda Error',
    });

    const remediationNotActiveErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'REMEDIATIONNOTTACTIVE' },
      label: 'Remediation Not Active',
    });

    const noRemediationErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'NOREMEDIATION' },
      label: 'No Remediation',
    });

    const standardNotEnabledErrorMetric = new Metric({
      namespace: 'ASR',
      metricName: 'RemediationOutcome',
      statistic: 'Sum',
      period: defaultDuration,
      dimensionsMap: { Outcome: 'STANDARDNOTENABLED' },
      label: 'Standard Not Enabled',
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
      expression: '(m1 * 30) / 60',
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
        ['m4']: standardNotEnabledErrorMetric,
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
    const snsAlarmTopic = new Topic(scope, 'ASR-Alarm-Topic', {
      displayName: 'ASR Alarm Topic (' + RESOURCE_PREFIX + ')',
      topicName: RESOURCE_PREFIX + '-ASR_Alarm_Topic',
      masterKey: props.kmsKey,
    });
    setCondition(snsAlarmTopic, this.isUsingCloudWatchMetricsAlarms);

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

    const controlIds = SC_REMEDIATIONS.map((remediation: IControl) => remediation.control);
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
* \`Remediation Not Active\`: The runbook associated with this remediation is not properly deployed in the solution's Admin and/or Member stack. Verify the solution's parameters.
* \`No Remediation\`: ASR does not currently implement a remediation for the executed finding.
* \`Standard Not Enabled\`: The Security Standard associated with the finding is not enabled in Security Hub. Navigate to the Security Hub console to activate the Standard.
* \`SSM Doc Failed\`: The remediation script failed to execute. Check the Orchestrator step function to determine which account the remediation was executed in, then view the SSM automation execution history for failures.

If there is an increase in \`NOREMEDIATION\` results, this indicates that remediations are being attempted for remediations not currently included in ASR. You should verify that this is not caused by a modified automatic remediation EventBridge rule.
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
          standardNotEnabledErrorMetric,
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
