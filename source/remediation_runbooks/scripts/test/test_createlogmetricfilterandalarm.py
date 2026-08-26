# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import CreateLogMetricFilterAndAlarm as logMetricAlarm
import CreateLogMetricFilterAndAlarm_createtopic as topicutil
import pytest
from moto import mock_aws

my_session = boto3.session.Session()
my_region = my_session.region_name or "us-east-1"


@mock_aws
def test_verify():
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
    context = {}

    # Create log group
    logs = boto3.client("logs", region_name=my_region)
    logs.create_log_group(logGroupName=event["LogGroupName"])

    # Create SNS topic
    sns = boto3.client("sns", region_name=my_region)
    sns.create_topic(Name="test-topic-name")

    logMetricAlarm.verify(event, context)

    # Verify metric filter was created
    filters = logs.describe_metric_filters(logGroupName=event["LogGroupName"])
    assert len(filters["metricFilters"]) == 1
    assert filters["metricFilters"][0]["filterName"] == event["FilterName"]

    # Verify alarm was created
    cloudwatch = boto3.client("cloudwatch", region_name=my_region)
    alarms = cloudwatch.describe_alarms(AlarmNames=[event["AlarmName"]])
    assert len(alarms["MetricAlarms"]) == 1
    assert alarms["MetricAlarms"][0]["AlarmName"] == event["AlarmName"]


@mock_aws
def test_put_metric_filter_pass():
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

    logs = boto3.client("logs", region_name=my_region)
    logs.create_log_group(logGroupName=event["LogGroupName"])

    logMetricAlarm.put_metric_filter(
        event["LogGroupName"],
        event["FilterName"],
        event["FilterPattern"],
        event["MetricName"],
        event["MetricNamespace"],
        event["MetricValue"],
    )

    # Verify metric filter was created
    filters = logs.describe_metric_filters(logGroupName=event["LogGroupName"])
    assert len(filters["metricFilters"]) == 1
    assert filters["metricFilters"][0]["filterName"] == event["FilterName"]
    assert filters["metricFilters"][0]["filterPattern"] == event["FilterPattern"]


@mock_aws
def test_put_metric_filter_error():
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

    # Test with invalid filter pattern to trigger error
    # Use a pattern that will cause moto to fail
    with pytest.raises(
        logMetricAlarm.MetricFilterCreationError
    ) as pytest_wrapped_exception:
        # Pass an invalid metric transformation that moto will reject
        logMetricAlarm.put_metric_filter(
            event["LogGroupName"],
            "",  # Empty filter name should trigger error
            event["FilterPattern"],
            event["MetricName"],
            event["MetricNamespace"],
            event["MetricValue"],
        )
    assert "Failed to create metric filter" in str(pytest_wrapped_exception.value)


@mock_aws
def test_put_metric_alarm():
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

    # Create SNS topic
    sns = boto3.client("sns", region_name=my_region)
    sns.create_topic(Name="test-topic-name")

    cloudwatch = boto3.client("cloudwatch", region_name=my_region)

    logMetricAlarm.put_metric_alarm(
        event["AlarmName"],
        event["AlarmDesc"],
        event["AlarmThreshold"],
        event["MetricName"],
        event["MetricNamespace"],
        event["TopicArn"],
    )

    # Verify alarm was created
    alarms = cloudwatch.describe_alarms(AlarmNames=[event["AlarmName"]])
    assert len(alarms["MetricAlarms"]) == 1
    alarm = alarms["MetricAlarms"][0]
    assert alarm["AlarmName"] == event["AlarmName"]
    assert alarm["AlarmDescription"] == event["AlarmDesc"]
    assert alarm["MetricName"] == event["MetricName"]
    assert alarm["Namespace"] == event["MetricNamespace"]


@mock_aws
def test_put_metric_alarm_error():
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

    # Test with invalid threshold to trigger error
    # Moto doesn't validate all alarm parameters, so we'll test with an invalid metric name
    with pytest.raises(
        logMetricAlarm.MetricAlarmCreationError
    ) as pytest_wrapped_exception:
        logMetricAlarm.put_metric_alarm(
            "",  # Empty alarm name should trigger error
            event["AlarmDesc"],
            event["AlarmThreshold"],
            event["MetricName"],
            event["MetricNamespace"],
            event["TopicArn"],
        )
    assert "Failed to create CloudWatch alarm" in str(pytest_wrapped_exception.value)


def topic_event():
    return {
        "TopicName": "sharr-test-topic",
        "KmsKeyArn": "arn:aws:kms:ap-northeast-1:111122223333:key/foobarbaz",
        "Region": "us-east-1",
        "AccountId": "111122223333",
    }


@mock_aws
def test_create_new_topic():
    sns_client = boto3.client("sns", region_name=my_region)
    ssm_client = boto3.client("ssm", region_name=my_region)

    event = {
        "TopicName": "sharr-test-topic",
        "KmsKeyArn": "arn:aws:kms:ap-northeast-1:111122223333:key/foobarbaz",
        "Region": my_region,
        "AccountId": "111122223333",
    }

    result = topicutil.create_encrypted_topic(event, {})

    # Verify topic was created
    topics = sns_client.list_topics()
    topic_arns = [t["TopicArn"] for t in topics["Topics"]]
    assert any(
        re.match(r"arn:aws:sns:[a-z0-9-]+:\d{12}:sharr-test-topic", arn)
        for arn in topic_arns
    )

    # Verify SSM parameter was created
    param = ssm_client.get_parameter(Name="/Solutions/SO0111/SNS_Topic_CIS3.x")
    assert re.match(
        r"arn:aws:sns:[a-z0-9-]+:\d{12}:sharr-test-topic",
        param["Parameter"]["Value"],
    )

    # Verify result structure
    assert "TopicArn" in result
    assert "ResourceArn" in result
    assert "ParameterArn" in result
    assert result["ResourceArn"] == result["TopicArn"]
    assert re.match(
        r"arn:aws:sns:[a-z0-9-]+:\d{12}:sharr-test-topic", result["TopicArn"]
    )

    # Verify parameter ARN format
    assert re.match(
        r"arn:aws:ssm:[a-z0-9-]+:\d{12}:parameter/Solutions/SO0111/SNS_Topic_CIS3\.x",
        result["ParameterArn"],
    )


@mock_aws
def test_ensure_log_group_exists_already_exists():
    logs = boto3.client("logs", region_name=my_region)
    logs.create_log_group(logGroupName="test_log")

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": False}


@mock_aws
def test_ensure_log_group_exists_creates_new():
    """Test ensure_log_group_exists when log group needs to be created"""
    logs = boto3.client("logs", region_name=my_region)

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": True}

    # Verify log group was created
    log_groups = logs.describe_log_groups(logGroupNamePrefix="test_log")
    assert len(log_groups["logGroups"]) == 1
    assert log_groups["logGroups"][0]["logGroupName"] == "test_log"


def test_ensure_log_group_exists_handles_access_denied():
    """Test ensure_log_group_exists handles AccessDeniedException gracefully"""
    from botocore.stub import Stubber

    logs = boto3.client("logs", region_name=my_region)
    stubber = Stubber(logs)

    # Simulate AccessDeniedException on describe_log_groups
    stubber.add_client_error(
        "describe_log_groups",
        service_error_code="AccessDeniedException",
        service_message="User is not authorized to perform: logs:DescribeLogGroups",
    )

    # Simulate successful create_log_group
    stubber.add_response(
        "create_log_group",
        {},
        expected_params={"logGroupName": "test_log"},
    )

    with stubber:
        result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
        assert result == {"exists": True, "created": True}


def test_ensure_log_group_exists_describe_fails_create_succeeds():
    """Test ensure_log_group_exists when describe fails with throttling but create succeeds"""
    from botocore.stub import Stubber

    logs = boto3.client("logs", region_name=my_region)
    stubber = Stubber(logs)

    # Simulate ThrottlingException on describe_log_groups (different from AccessDenied)
    stubber.add_client_error(
        "describe_log_groups",
        service_error_code="ThrottlingException",
        service_message="Rate exceeded",
    )

    with stubber:
        # This should raise LogGroupVerificationError since it's not AccessDeniedException
        with pytest.raises(logMetricAlarm.LogGroupVerificationError) as exc_info:
            logMetricAlarm.ensure_log_group_exists(logs, "test_log")
        assert "Cannot create or verify log group" in str(exc_info.value)


@mock_aws
def test_ensure_log_group_exists_already_exists_during_creation():
    """Test ensure_log_group_exists when log group is created by another process"""
    logs = boto3.client("logs", region_name=my_region)

    # Pre-create the log group to simulate it being created by another process
    logs.create_log_group(logGroupName="test_log")

    result = logMetricAlarm.ensure_log_group_exists(logs, "test_log")
    assert result == {"exists": True, "created": False}


@mock_aws
def test_create_topic_returns_resource_arn():
    """Test that create_encrypted_topic returns ResourceArn in correct format"""
    event = {
        "TopicName": "test-topic",
        "KmsKeyArn": "arn:aws:kms:us-east-1:111111111111:key/test-key-id",
        "Region": my_region,
        "AccountId": "111111111111",
    }

    result = topicutil.create_encrypted_topic(event, {})

    # Verify ResourceArn is present and matches TopicArn
    assert "ResourceArn" in result
    assert result["ResourceArn"] == result["TopicArn"]
    assert re.match(r"arn:aws:sns:[a-z0-9-]+:\d{12}:test-topic", result["ResourceArn"])

    # Verify ParameterArn is present
    assert "ParameterArn" in result
    assert re.match(
        r"arn:aws:ssm:[a-z0-9-]+:\d{12}:parameter/Solutions/SO0111/SNS_Topic_CIS3\.x",
        result["ParameterArn"],
    )


@mock_aws
def test_verify_returns_log_group_and_alarm_arns():
    """Test that verify returns LogGroupArn and AlarmArn"""
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

    # Create log group
    logs = boto3.client("logs", region_name=my_region)
    logs.create_log_group(logGroupName=event["LogGroupName"])

    # Create SNS topic
    sns = boto3.client("sns", region_name=my_region)
    sns.create_topic(Name="test-topic-name")

    result = logMetricAlarm.verify(event, {})

    # Verify ARNs are present
    assert "LogGroupArn" in result
    assert "AlarmArn" in result

    # Verify log group ARN format
    assert re.match(
        r"arn:aws:logs:[a-z0-9-]+:\d{12}:log-group:test_log", result["LogGroupArn"]
    )

    # Verify alarm ARN format
    assert re.match(
        r"arn:aws:cloudwatch:[a-z0-9-]+:\d{12}:alarm:test_alarm", result["AlarmArn"]
    )


@mock_aws
def test_put_metric_alarm_returns_arn():
    """Test that put_metric_alarm returns alarm ARN"""
    event = {
        "AlarmName": "test_alarm",
        "AlarmDesc": "alarm_desc",
        "AlarmThreshold": 1,
        "MetricName": "test_metric",
        "MetricNamespace": "test_metricnamespace",
        "TopicArn": "arn:aws:sns:us-east-1:111111111111:test-topic-name",
    }

    # Create SNS topic
    sns = boto3.client("sns", region_name=my_region)
    sns.create_topic(Name="test-topic-name")

    alarm_arn = logMetricAlarm.put_metric_alarm(
        event["AlarmName"],
        event["AlarmDesc"],
        event["AlarmThreshold"],
        event["MetricName"],
        event["MetricNamespace"],
        event["TopicArn"],
    )

    # Verify ARN format
    assert re.match(r"arn:aws:cloudwatch:[a-z0-9-]+:\d{12}:alarm:test_alarm", alarm_arn)
