# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
import os

import boto3
from botocore.config import Config


class LogGroupCreationError(Exception):
    pass


class LogGroupVerificationError(Exception):
    pass


class MetricFilterCreationError(Exception):
    pass


class MetricAlarmCreationError(Exception):
    pass


class RemediationError(Exception):
    pass


boto_config = Config(retries={"max_attempts": 10, "mode": "standard"})

log = logging.getLogger()
LOG_LEVEL = str(os.getenv("LogLevel", "INFO"))
log.setLevel(LOG_LEVEL)


def get_service_client(service_name):
    """
    Returns the service client for given the service name
    :param service_name: name of the service
    :return: service client
    """
    log.debug("Getting the service client for service: {}".format(service_name))
    return boto3.client(service_name, config=boto_config)


def _get_error_code(exception):
    return getattr(exception, "response", {}).get("Error", {}).get("Code", "")


def _check_log_group_exists(logs_client, log_group_name):
    response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
    for group in response.get("logGroups", []):
        if group["logGroupName"] == log_group_name:
            return True
    return False


def _create_log_group_with_fallback(logs_client, log_group_name):
    try:
        logs_client.create_log_group(logGroupName=log_group_name)
        log.info(f"Successfully created log group {log_group_name}")
        return {"exists": True, "created": True}
    except Exception as create_error:
        error_code = _get_error_code(create_error)
        if error_code == "ResourceAlreadyExistsException":
            log.info(f"Log group {log_group_name} already exists")
            return {"exists": True, "created": False}
        else:
            log.error(f"Failed to create log group: {str(create_error)}")
            raise LogGroupCreationError(
                f"Cannot create log group {log_group_name}: {str(create_error)}"
            )


def ensure_log_group_exists(logs_client, log_group_name):
    """
    Ensures a CloudWatch log group exists, creating it if necessary.

    :param logs_client: CloudWatch Logs client
    :param log_group_name: Name of the log group to ensure exists
    :return: dict with 'exists' (bool) and 'created' (bool) keys indicating the result
    :raises LogGroupCreationError: If log group creation fails
    :raises LogGroupVerificationError: If log group existence cannot be verified
    """
    try:
        log.info(f"Checking if log group {log_group_name} exists")
        if _check_log_group_exists(logs_client, log_group_name):
            log.info(f"Log group {log_group_name} already exists")
            return {"exists": True, "created": False}

        log.info(f"Log group {log_group_name} not found, creating it")
        logs_client.create_log_group(logGroupName=log_group_name)
        log.info(f"Successfully created log group {log_group_name}")
        return {"exists": True, "created": True}

    except Exception as e:
        error_code = _get_error_code(e)

        if error_code == "AccessDeniedException" and "DescribeLogGroups" in str(e):
            log.info(
                f"Cannot describe log groups due to permissions, attempting to create {log_group_name} directly"
            )
            return _create_log_group_with_fallback(logs_client, log_group_name)
        elif error_code == "ResourceAlreadyExistsException":
            log.info(f"Log group {log_group_name} was created by another process")
            return {"exists": True, "created": False}
        else:
            log.error(f"Failed to ensure log group exists: {str(e)}")
            raise LogGroupVerificationError(
                f"Cannot create or verify log group {log_group_name}: {str(e)}"
            )


def put_metric_filter(
    cw_log_group,
    filter_name,
    filter_pattern,
    metric_name,
    metric_namespace,
    metric_value,
):
    """
    Puts the metric filter on the CloudWatch log group with provided values
    :param cw_log_group: Name of the CloudWatch log group
    :param filter_name: Name of the filter
    :param filter_pattern: Pattern for the filter
    :param metric_name: Name of the metric
    :param metric_namespace: Namespace where metric is logged
    :param metric_value: Value to be logged for the metric
    """
    logs_client = get_service_client("logs")
    log.info(f"Creating metric filter '{filter_name}' for log group '{cw_log_group}'")
    log.debug(
        f"Filter details: pattern='{filter_pattern}', metric='{metric_name}', namespace='{metric_namespace}', value='{metric_value}'"
    )

    # Ensure log group exists first
    log_group_result = ensure_log_group_exists(logs_client, cw_log_group)
    if not log_group_result["exists"]:
        raise LogGroupVerificationError(
            f"Cannot proceed without log group {cw_log_group}"
        )

    if log_group_result["created"]:
        log.info(f"Log group {cw_log_group} was created for this operation")
    else:
        log.info(f"Using existing log group {cw_log_group}")

    try:
        logs_client.put_metric_filter(
            logGroupName=cw_log_group,
            filterName=filter_name,
            filterPattern=filter_pattern,
            metricTransformations=[
                {
                    "metricName": metric_name,
                    "metricNamespace": metric_namespace,
                    "metricValue": str(metric_value),
                    "unit": "Count",
                }
            ],
        )
        log.info(
            f"Successfully created metric filter '{filter_name}' on log group '{cw_log_group}'"
        )

    except Exception as e:
        error_msg = f"Failed to create metric filter '{filter_name}' on log group '{cw_log_group}': {str(e)}"
        log.error(error_msg)
        raise MetricFilterCreationError(error_msg)


def put_metric_alarm(
    alarm_name, alarm_desc, alarm_threshold, metric_name, metric_namespace, topic_arn
):
    """
    Puts the metric alarm for the metric name with provided values
    :param alarm_name: Name for the alarm
    :param alarm_desc: Description for the alarm
    :param alarm_threshold: Threshold value for the alarm
    :param metric_name: Name of the metric
    :param metric_namespace: Namespace where metric is logged
    :param topic_arn: SNS topic ARN for alarm notifications
    """
    cw_client = get_service_client("cloudwatch")
    log.info(
        f"Creating CloudWatch alarm '{alarm_name}' for metric '{metric_name}' in namespace '{metric_namespace}'"
    )
    log.debug(f"Alarm details: threshold={alarm_threshold}, topic={topic_arn}")

    try:
        cw_client.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_desc,
            ActionsEnabled=True,
            OKActions=[topic_arn],
            AlarmActions=[topic_arn],
            MetricName=metric_name,
            Namespace=metric_namespace,
            Statistic="Sum",
            Period=300,
            Unit="Count",
            EvaluationPeriods=12,
            DatapointsToAlarm=1,
            Threshold=alarm_threshold,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            TreatMissingData="notBreaching",
        )
        log.info(f"Successfully created CloudWatch alarm '{alarm_name}'")

    except Exception as e:
        error_msg = f"Failed to create CloudWatch alarm '{alarm_name}': {str(e)}"
        log.error(error_msg)
        raise MetricAlarmCreationError(error_msg)


def verify(event, _):
    log.info("Starting CreateLogMetricFilterAndAlarm remediation")
    log.debug(f"Event parameters: {event}")

    required_params = [
        "FilterName",
        "FilterPattern",
        "MetricName",
        "MetricNamespace",
        "MetricValue",
        "AlarmName",
        "AlarmDesc",
        "AlarmThreshold",
        "LogGroupName",
        "TopicArn",
    ]

    for param in required_params:
        if param not in event:
            raise ValueError(f"Missing required parameter: {param}")

    filter_name = event["FilterName"]
    filter_pattern = event["FilterPattern"]
    metric_name = event["MetricName"]
    metric_namespace = event["MetricNamespace"]
    metric_value = event["MetricValue"]
    alarm_name = event["AlarmName"]
    alarm_desc = event["AlarmDesc"]
    alarm_threshold = event["AlarmThreshold"]
    cw_log_group = event["LogGroupName"]
    topic_arn = event["TopicArn"]

    try:
        log.info("Step 1: Creating metric filter")
        put_metric_filter(
            cw_log_group,
            filter_name,
            filter_pattern,
            metric_name,
            metric_namespace,
            metric_value,
        )

        log.info("Step 2: Creating CloudWatch alarm")
        put_metric_alarm(
            alarm_name,
            alarm_desc,
            alarm_threshold,
            metric_name,
            metric_namespace,
            topic_arn,
        )

        success_message = f"Successfully created metric filter '{filter_name}' and alarm '{alarm_name}' for log group '{cw_log_group}'"
        log.info(success_message)

        return {
            "response": {
                "message": success_message,
                "status": "Success",
                "filterName": filter_name,
                "alarmName": alarm_name,
                "logGroupName": cw_log_group,
                "metricName": metric_name,
            }
        }

    except Exception as e:
        error_message = f"Failed to create metric filter and alarm: {str(e)}"
        log.error(error_message)
        raise RemediationError(error_message)
