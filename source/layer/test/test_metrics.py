# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

import boto3
from botocore.stub import Stubber
from layer.metrics import Metrics

from . import file_utilities as utils

test_data = "test/test_json_data/"


def get_region():
    return os.getenv("AWS_DEFAULT_REGION")


mock_ssm_get_parameter_uuid = {
    "Parameter": {
        "Name": "/Solutions/SO0111/anonymous_metrics_uuid",
        "Type": "String",
        "Value": "11111111-1111-1111-1111-111111111111",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}:111111111111:parameter/Solutions/SO0111/anonymous_metrics_uuid",
        "DataType": "text",
    }
}
mock_ssm_get_parameter_version = {
    "Parameter": {
        "Name": "/Solutions/SO0111/solution_version",
        "Type": "String",
        "Value": "v1.2.0TEST",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}1:111111111111:parameter/Solutions/SO0111/solution_version",
        "DataType": "text",
    }
}

mock_ssm_get_parameter_sendmetrics_yes = {
    "Parameter": {
        "Name": "/Solutions/SO0111/sendAnonymizedMetrics",
        "Type": "String",
        "Value": "Yes",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}:111111111111:parameter/Solutions/SO0111/sendAnonymizedMetrics",
        "DataType": "text",
    }
}

mock_ssm_get_parameter_sendmetrics_no = {
    "Parameter": {
        "Name": "/Solutions/SO0111/sendAnonymizedMetrics",
        "Type": "String",
        "Value": "No",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": f"arn:aws:ssm:{get_region()}:111111111111:parameter/Solutions/SO0111/sendAnonymizedMetrics",
        "DataType": "text",
    }
}

mock_ssm_get_parameter_sendmetrics_badvalue = {
    "Parameter": {
        "Name": "/Solutions/SO0111/sendAnonymizedMetrics",
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
def test_metrics_construction(mocker):
    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_yes)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_uuid)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_version)
    ssmc_s.activate()

    mocker.patch("layer.metrics.Metrics.connect_to_ssm", return_value=ssmc)

    metrics = Metrics("unit-test")

    assert metrics.solution_uuid == "11111111-1111-1111-1111-111111111111"
    assert metrics.solution_version == "v1.2.0TEST"


# ------------------------------------------------------------------------------
# This test verifies that event data is parsed correctly
# ------------------------------------------------------------------------------
def test_get_metrics_from_finding(mocker):
    expected_response = {
        "generator_id": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3",
        "type": "1.3 Ensure credentials unused for 90 days or greater are disabled",
        "productArn": "arn:aws:securityhub:"
        + get_region()
        + "::product/aws/securityhub",
        "finding_triggered_by": "unit-test",
        "region": mocker.ANY,
        "custom_action_name": "MyCustomAction",
    }

    event = {
        "Finding": utils.load_test_data(test_data + "CIS-1.3.json", get_region())
        .get("detail")
        .get("findings")[0],
        "CustomActionName": "MyCustomAction",
    }

    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_yes)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_uuid)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_version)
    ssmc_s.activate()

    mocker.patch("layer.metrics.Metrics.connect_to_ssm", return_value=ssmc)

    metrics = Metrics("unit-test")

    assert metrics.get_metrics_from_event(event) == expected_response


# ------------------------------------------------------------------------------
# This test verifies that sendAnonymizedMetrics defaults to no when the value is
# other than yes or no.
# ------------------------------------------------------------------------------
def test_validate_ambiguous_sendanonymousmetrics(mocker):
    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_badvalue)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_uuid)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_version)
    ssmc_s.activate()

    mocker.patch("layer.metrics.Metrics.connect_to_ssm", return_value=ssmc)

    metrics = Metrics("unit-test")

    assert metrics.send_anonymous_metrics_enabled() is False


# ------------------------------------------------------------------------------
# This test verifies that send_metrics will post metrics when enabled via ssm
# ------------------------------------------------------------------------------
def test_send_metrics(mocker):
    expected_response = {
        "Solution": "SO0111",
        "UUID": "11111111-1111-1111-1111-111111111111",
        "TimeStamp": mocker.ANY,
        "Data": {
            "generator_id": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3",
            "type": "1.3 Ensure credentials unused for 90 days or greater are disabled",
            "productArn": mocker.ANY,
            "finding_triggered_by": "unit-test",
            "region": mocker.ANY,
            "custom_action_name": "MyCustomAction",
        },
        "Version": "v1.2.0TEST",
    }

    event = {
        "Finding": utils.load_test_data(test_data + "CIS-1.3.json", get_region())
        .get("detail")
        .get("findings")[0],
        "CustomActionName": "MyCustomAction",
    }

    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_yes)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_uuid)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_version)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_yes)
    ssmc_s.activate()

    mocker.patch("layer.metrics.Metrics.connect_to_ssm", return_value=ssmc)

    metrics = Metrics("unit-test")
    metrics_data = metrics.get_metrics_from_event(event)
    assert metrics_data == {
        "generator_id": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3",
        "type": "1.3 Ensure credentials unused for 90 days or greater are disabled",
        "productArn": f"arn:aws:securityhub:{get_region()}::product/aws/securityhub",
        "finding_triggered_by": "unit-test",
        "region": get_region(),
        "custom_action_name": "MyCustomAction",
    }

    send_metrics = mocker.patch(
        "layer.metrics.Metrics.post_metrics_to_api", return_value=None
    )

    metrics.send_metrics(metrics_data)

    send_metrics.assert_called_with(expected_response)


# ------------------------------------------------------------------------------
# This test verifies that send_metrics takes the value from the SSM parameter
# WHEN METRICS ARE SENT. It does not assume that if the metrics object exists
# then send metrics is enabled.
# ------------------------------------------------------------------------------
def test_do_not_send_metrics(mocker):
    event = {
        "Finding": utils.load_test_data(test_data + "CIS-1.3.json", get_region())
        .get("detail")
        .get("findings")[0],
        "CustomActionName": "MyCustomAction",
    }

    ssmc = boto3.client("ssm", region_name=get_region())
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_yes)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_uuid)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_version)
    ssmc_s.add_response("get_parameter", mock_ssm_get_parameter_sendmetrics_no)
    ssmc_s.activate()

    mocker.patch("layer.metrics.Metrics.connect_to_ssm", return_value=ssmc)

    metrics = Metrics("unit-test")
    metrics_data = metrics.get_metrics_from_event(event)
    assert metrics_data == {
        "generator_id": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3",
        "type": "1.3 Ensure credentials unused for 90 days or greater are disabled",
        "productArn": f"arn:aws:securityhub:{get_region()}::product/aws/securityhub",
        "finding_triggered_by": "unit-test",
        "region": get_region(),
        "custom_action_name": "MyCustomAction",
    }

    send_metrics = mocker.patch(
        "layer.metrics.Metrics.post_metrics_to_api", return_value=None
    )

    metrics.send_metrics(metrics_data)

    send_metrics.assert_not_called()
