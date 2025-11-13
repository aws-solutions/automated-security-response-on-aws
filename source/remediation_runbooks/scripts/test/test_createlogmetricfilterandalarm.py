# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Dict

import boto3
import botocore.session
import CreateLogMetricFilterAndAlarm as logMetricAlarm
import CreateLogMetricFilterAndAlarm_createtopic as topicutil
import pytest
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


def test_verify(mocker):
    event = {
        "FilterName": "test_filter",
        "FilterPattern": "test_pattern",
        "MetricName": "test_metric",
        "MetricNamespace": "test_metricnamespace",
        "MetricValue": "test_metric_value",
        "AlarmName": "test_alarm",
        "AlarmDesc": "alarm_desc",
        "AlarmThreshold": "alarm_threshold",
        "LogGroupName": "test_log",
        "TopicArn": "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    }
    context: Dict[str, str] = {}
    mocker.patch("CreateLogMetricFilterAndAlarm.put_metric_filter")
    mocker.patch("CreateLogMetricFilterAndAlarm.put_metric_alarm")
    metric_filter_spy = mocker.spy(logMetricAlarm, "put_metric_filter")
    metric_alarm_spy = mocker.spy(logMetricAlarm, "put_metric_alarm")
    logMetricAlarm.verify(event, context)
    metric_filter_spy.assert_called_once_with(
        "test_log",
        "test_filter",
        "test_pattern",
        "test_metric",
        "test_metricnamespace",
        "test_metric_value",
    )
    metric_alarm_spy.assert_called_once_with(
        "test_alarm",
        "alarm_desc",
        "alarm_threshold",
        "test_metric",
        "test_metricnamespace",
        "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    )


def test_put_metric_filter_pass(mocker):
    event = {
        "FilterName": "test_filter",
        "FilterPattern": "test_pattern",
        "MetricName": "test_metric",
        "MetricNamespace": "test_metricnamespace",
        "MetricValue": "test_metric_value",
        "AlarmName": "test_alarm",
        "AlarmDesc": "alarm_desc",
        "AlarmThreshold": "alarm_threshold",
        "LogGroupName": "test_log",
        "TopicArn": "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    logs_stubber.add_response(
        "describe_log_groups",
        {
            "logGroups": [
                {
                    "logGroupName": event["LogGroupName"],
                    "creationTime": 1234567890,
                    "retentionInDays": 14,
                    "metricFilterCount": 0,
                    "arn": f"arn:aws:logs:us-east-1:111111111111:log-group:{event['LogGroupName']}:*",
                    "storedBytes": 0,
                }
            ]
        },
        {"logGroupNamePrefix": event["LogGroupName"]},
    )

    logs_stubber.add_response(
        "put_metric_filter",
        {},
        {
            "logGroupName": event["LogGroupName"],
            "filterName": event["FilterName"],
            "filterPattern": event["FilterPattern"],
            "metricTransformations": [
                {
                    "metricName": event["MetricName"],
                    "metricNamespace": event["MetricNamespace"],
                    "metricValue": str(event["MetricValue"]),
                    "unit": "Count",
                }
            ],
        },
    )
    logs_stubber.activate()
    mocker.patch("CreateLogMetricFilterAndAlarm.get_service_client", return_value=logs)
    logMetricAlarm.put_metric_filter(
        event["LogGroupName"],
        event["FilterName"],
        event["FilterPattern"],
        event["MetricName"],
        event["MetricNamespace"],
        event["MetricValue"],
    )

    logs_stubber.assert_no_pending_responses()
    logs_stubber.deactivate()


def test_put_metric_filter_error(mocker):
    event = {
        "FilterName": "test_filter",
        "FilterPattern": "test_pattern",
        "MetricName": "test_metric",
        "MetricNamespace": "test_metricnamespace",
        "MetricValue": "test_metric_value",
        "AlarmName": "test_alarm",
        "AlarmDesc": "alarm_desc",
        "AlarmThreshold": "alarm_threshold",
        "LogGroupName": "test_log",
        "TopicArn": "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    logs_stubber.add_response(
        "describe_log_groups",
        {
            "logGroups": [
                {
                    "logGroupName": event["LogGroupName"],
                    "creationTime": 1234567890,
                    "retentionInDays": 14,
                    "metricFilterCount": 0,
                    "arn": f"arn:aws:logs:us-east-1:111111111111:log-group:{event['LogGroupName']}:*",
                    "storedBytes": 0,
                }
            ]
        },
        {"logGroupNamePrefix": event["LogGroupName"]},
    )

    logs_stubber.add_client_error("put_metric_filter", "CannotAddFilter")

    logs_stubber.activate()
    mocker.patch("CreateLogMetricFilterAndAlarm.get_service_client", return_value=logs)
    with pytest.raises(
        logMetricAlarm.MetricFilterCreationError
    ) as pytest_wrapped_exception:
        logMetricAlarm.put_metric_filter(
            event["LogGroupName"],
            event["FilterName"],
            event["FilterPattern"],
            event["MetricName"],
            event["MetricNamespace"],
            event["MetricValue"],
        )
    assert "Failed to create metric filter" in str(pytest_wrapped_exception.value)


def test_put_metric_alarm(mocker):
    event = {
        "FilterName": "test_filter",
        "FilterPattern": "test_pattern",
        "MetricName": "test_metric",
        "MetricNamespace": "test_metricnamespace",
        "MetricValue": "test_metric_value",
        "AlarmName": "test_alarm",
        "AlarmDesc": "alarm_desc",
        "AlarmThreshold": 1,
        "LogGroupName": "test_log",
        "TopicArn": "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    cloudwatch = botocore.session.get_session().create_client(
        "cloudwatch", config=BOTO_CONFIG
    )
    cloudwatch_stubber = Stubber(cloudwatch)

    cloudwatch_stubber.add_response(
        "put_metric_alarm",
        {},
        {
            "AlarmName": event["AlarmName"],
            "AlarmDescription": event["AlarmDesc"],
            "ActionsEnabled": True,
            "OKActions": ["arn:aws:sns:us-east-1:111111111111:test-topic-name"],
            "AlarmActions": ["arn:aws:sns:us-east-1:111111111111:test-topic-name"],
            "MetricName": event["MetricName"],
            "Namespace": event["MetricNamespace"],
            "Statistic": "Sum",
            "Period": 300,
            "Unit": "Count",
            "EvaluationPeriods": 12,
            "DatapointsToAlarm": 1,
            "Threshold": (event["AlarmThreshold"]),
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "TreatMissingData": "notBreaching",
        },
    )
    cloudwatch_stubber.activate()
    mocker.patch(
        "CreateLogMetricFilterAndAlarm.get_service_client", return_value=cloudwatch
    )
    logMetricAlarm.put_metric_alarm(
        event["AlarmName"],
        event["AlarmDesc"],
        event["AlarmThreshold"],
        event["MetricName"],
        event["MetricNamespace"],
        event["TopicArn"],
    )
    cloudwatch_stubber.assert_no_pending_responses()
    cloudwatch_stubber.deactivate()


def test_put_metric_alarm_error(mocker):
    event = {
        "FilterName": "test_filter",
        "FilterPattern": "test_pattern",
        "MetricName": "test_metric",
        "MetricNamespace": "test_metricnamespace",
        "MetricValue": "test_metric_value",
        "AlarmName": "test_alarm",
        "AlarmDesc": "alarm_desc",
        "AlarmThreshold": 1,
        "LogGroupName": "test_log",
        "TopicArn": "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    cloudwatch = botocore.session.get_session().create_client(
        "cloudwatch", config=BOTO_CONFIG
    )
    cloudwatch_stubber = Stubber(cloudwatch)

    cloudwatch_stubber.add_client_error("put_metric_alarm", "CannotAddAlarm")
    cloudwatch_stubber.activate()
    mocker.patch(
        "CreateLogMetricFilterAndAlarm.get_service_client", return_value=cloudwatch
    )

    with pytest.raises(
        logMetricAlarm.MetricAlarmCreationError
    ) as pytest_wrapped_exception:
        logMetricAlarm.put_metric_alarm(
            event["AlarmName"],
            event["AlarmDesc"],
            event["AlarmThreshold"],
            event["MetricName"],
            event["MetricNamespace"],
            event["TopicArn"],
        )
    assert "Failed to create CloudWatch alarm" in str(pytest_wrapped_exception.value)
    cloudwatch_stubber.deactivate()


def topic_event():
    return {
        "topic_name": "sharr-test-topic",
        "kms_key_arn": "arn:aws:kms:ap-northeast-1:111122223333:key/foobarbaz",
    }


def test_create_new_topic(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    ssm_client = botocore.session.get_session().create_client("ssm", config=BOTO_CONFIG)
    ssm_stubber = Stubber(ssm_client)
    ssm_stubber.add_response(
        "put_parameter",
        {},
        {
            "Name": "/Solutions/SO0111/SNS_Topic_CIS3.x",
            "Description": "SNS Topic for AWS Config updates",
            "Type": "String",
            "Overwrite": True,
            "Value": "arn:aws:sns:us-east-1:111111111111:sharr-test-topic",
        },
    )
    ssm_stubber.activate()

    sns_client = botocore.session.get_session().create_client("sns", config=BOTO_CONFIG)
    sns_stubber = Stubber(sns_client)
    sns_stubber.add_response(
        "create_topic",
        {"TopicArn": "arn:aws:sns:us-east-1:111111111111:sharr-test-topic"},
    )
    sns_stubber.add_response("set_topic_attributes", {})
    sns_stubber.activate()
    mocker.patch(
        "CreateLogMetricFilterAndAlarm_createtopic.connect_to_ssm",
        return_value=ssm_client,
    )
    mocker.patch(
        "CreateLogMetricFilterAndAlarm_createtopic.connect_to_sns",
        return_value=sns_client,
    )

    assert topicutil.create_encrypted_topic(topic_event(), {}) == {
        "topic_arn": "arn:aws:sns:us-east-1:111111111111:sharr-test-topic"
    }


def test_ensure_log_group_exists_already_exists(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    logs_stubber.add_response(
        "describe_log_groups",
        {
            "logGroups": [
                {
                    "logGroupName": "test_log",
                    "creationTime": 1234567890,
                    "retentionInDays": 14,
                    "metricFilterCount": 0,
                    "arn": "arn:aws:logs:us-east-1:111111111111:log-group:test_log:*",
                    "storedBytes": 0,
                }
            ]
        },
        {"logGroupNamePrefix": "test_log"},
    )
    logs_stubber.activate()

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": False}
    logs_stubber.assert_no_pending_responses()
    logs_stubber.deactivate()


def test_ensure_log_group_exists_creates_new(mocker):
    """Test ensure_log_group_exists when log group needs to be created"""
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    # First call returns empty (log group doesn't exist)
    logs_stubber.add_response(
        "describe_log_groups", {"logGroups": []}, {"logGroupNamePrefix": "test_log"}
    )

    # Second call creates the log group
    logs_stubber.add_response("create_log_group", {}, {"logGroupName": "test_log"})

    logs_stubber.activate()

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": True}
    logs_stubber.assert_no_pending_responses()
    logs_stubber.deactivate()


def test_ensure_log_group_exists_handles_access_denied(mocker):
    """Test ensure_log_group_exists handles AccessDeniedException gracefully"""
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    # First call fails with AccessDeniedException that contains "DescribeLogGroups"
    logs_stubber.add_client_error(
        "describe_log_groups",
        "AccessDeniedException",
        "User is not authorized to perform: logs:DescribeLogGroups",
    )

    # Code will then try to create the log group, which also fails with AccessDeniedException
    logs_stubber.add_client_error("create_log_group", "AccessDeniedException")

    logs_stubber.activate()

    # This should raise a LogGroupCreationError because create_log_group fails
    with pytest.raises(logMetricAlarm.LogGroupCreationError) as exc_info:
        logMetricAlarm.ensure_log_group_exists(logs, "test_log")

    assert "Cannot create log group test_log" in str(exc_info.value)
    logs_stubber.assert_no_pending_responses()
    logs_stubber.deactivate()


def test_ensure_log_group_exists_describe_fails_create_succeeds(mocker):
    """Test ensure_log_group_exists when describe fails but create succeeds"""
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    # First call fails with AccessDeniedException that contains "DescribeLogGroups"
    logs_stubber.add_client_error(
        "describe_log_groups",
        "AccessDeniedException",
        "User is not authorized to perform: logs:DescribeLogGroups",
    )

    # Code will then try to create the log group, which succeeds
    logs_stubber.add_response("create_log_group", {}, {"logGroupName": "test_log"})

    logs_stubber.activate()

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": True}
    logs_stubber.assert_no_pending_responses()
    logs_stubber.deactivate()


def test_ensure_log_group_exists_already_exists_during_creation(mocker):
    """Test ensure_log_group_exists when log group is created by another process"""
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)
    logs = botocore.session.get_session().create_client("logs", config=BOTO_CONFIG)
    logs_stubber = Stubber(logs)

    # First call returns empty (log group doesn't exist)
    logs_stubber.add_response(
        "describe_log_groups", {"logGroups": []}, {"logGroupNamePrefix": "test_log"}
    )

    # Creation fails because it already exists (created by another process)
    logs_stubber.add_client_error("create_log_group", "ResourceAlreadyExistsException")

    logs_stubber.activate()

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": False}
    logs_stubber.assert_no_pending_responses()
    logs_stubber.deactivate()
