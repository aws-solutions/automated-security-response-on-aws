# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

import boto3
from botocore.stub import Stubber
from layer.cloudwatch_metrics import CloudWatchMetrics

test_data = "test/test_json_data/"


def get_region():
    return os.getenv("AWS_DEFAULT_REGION")


mock_ssm_get_parameter_send_cloudwatch_metrics_yes = {
    "Parameter": {
        "Name": "/Solutions/SO0111/sendCloudwatchMetrics",
        "Type": "String",
        "Value": "Yes",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}:111111111111:parameter/Solutions/SO0111/sendAnonymizedMetrics",
        "DataType": "text",
    }
}

mock_ssm_get_parameter_send_cloudwatch_no = {
    "Parameter": {
        "Name": "/Solutions/SO0111/sendCloudwatchMetrics",
        "Type": "String",
        "Value": "No",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}:111111111111:parameter/Solutions/SO0111/sendAnonymizedMetrics",
        "DataType": "text",
    }
}

mock_ssm_get_parameter_send_cloudwatch_bad_value = {
    "Parameter": {
        "Name": "/Solutions/SO0111/sendCloudwatchMetrics",
        "Type": "String",
        "Value": "slartibartfast",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}:111111111111:parameter/Solutions/SO0111/sendAnonymizedMetrics",
        "DataType": "text",
    }
}


# ------------------------------------------------------------------------------
# This test verifies that the metrics object is constructed correctly
# ------------------------------------------------------------------------------
def test_cw_metrics_construction(mocker):
    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        "get_parameter", mock_ssm_get_parameter_send_cloudwatch_metrics_yes
    )
    ssmc_s.activate()

    mocker.patch(
        "layer.cloudwatch_metrics.CloudWatchMetrics.init_ssm_client", return_value=ssmc
    )

    metrics = CloudWatchMetrics()

    assert metrics.metrics_enabled is True


# ------------------------------------------------------------------------------
# This test verifies that sendAnonymizedMetrics defaults to no when the value is
# other than yes or no.
# ------------------------------------------------------------------------------
def test_validate_ambiguous_sendanonymousmetrics(mocker):
    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        "get_parameter", mock_ssm_get_parameter_send_cloudwatch_bad_value
    )
    ssmc_s.activate()

    mocker.patch(
        "layer.cloudwatch_metrics.CloudWatchMetrics.init_ssm_client", return_value=ssmc
    )

    metrics = CloudWatchMetrics()

    assert metrics.send_cloudwatch_metrics_enabled() is False


# ------------------------------------------------------------------------------
# This test verifies that send_metrics will post metrics when enabled via ssm
# ------------------------------------------------------------------------------
def test_send_metrics(mocker):
    event_state = "SUCCESS"

    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        "get_parameter", mock_ssm_get_parameter_send_cloudwatch_metrics_yes
    )
    ssmc_s.activate()

    mocker.patch(
        "layer.cloudwatch_metrics.CloudWatchMetrics.init_ssm_client", return_value=ssmc
    )

    cloudwatch = boto3.client("cloudwatch")
    cloudwatch_s = Stubber(cloudwatch)
    cloudwatch_s.add_response("put_metric_data", {})
    cloudwatch_s.activate()

    mocker.patch(
        "layer.cloudwatch_metrics.CloudWatchMetrics.init_cloudwatch_client",
        return_value=cloudwatch,
    )

    metrics = CloudWatchMetrics()
    metric_data = {
        "MetricName": "Remediations",
        "Dimensions": [
            {
                "Name": "Outcome",
                "Value": event_state,
            },
        ],
        "Unit": "Count",
        "Value": 1,
    }

    metrics.send_metric(metric_data)
    cloudwatch_s.assert_no_pending_responses()
