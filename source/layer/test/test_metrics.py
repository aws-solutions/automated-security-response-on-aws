# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import urllib.parse
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from botocore.exceptions import ClientError

MOCK_ACCOUNT_ID = "123456789012"
MOCK_STACK_ID = "test-stack-id"
# Set environment variable before importing metrics
os.environ["AWS_ACCOUNT_ID"] = MOCK_ACCOUNT_ID
os.environ["STACK_ID"] = MOCK_STACK_ID

import boto3
import pytest
from layer.metrics import Metrics
from moto import mock_aws


def get_region():
    return os.getenv("AWS_DEFAULT_REGION", "us-east-1")


@mock_aws
def test_metrics_construction_with_existing_parameters():
    """Test metrics construction when both UUID and version parameters exist"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/metrics_uuid",
        Value="11111111-1111-1111-1111-111111111111",
        Type="String",
    )
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    # ACT
    metrics = Metrics()

    # ASSERT
    assert metrics.solution_uuid == "11111111-1111-1111-1111-111111111111"
    assert metrics.solution_version == "v1.2.0TEST"


@mock_aws
def test_metrics_construction_creates_new_uuid():
    """Test metrics construction creates new UUID when parameter doesn't exist"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    # ACT
    metrics = Metrics()

    # ASSERT
    assert metrics.solution_uuid is not None
    assert metrics.solution_version == "v1.2.0TEST"

    # Verify new parameter was created
    response = ssm.get_parameter(Name="/Solutions/SO0111/metrics_uuid")
    assert response["Parameter"]["Value"] == metrics.solution_uuid


@mock_aws
def test_metrics_construction_migrates_old_uuid():
    """Test metrics construction migrates UUID from old parameter"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    old_uuid = "22222222-2222-2222-2222-222222222222"
    ssm.put_parameter(
        Name="/Solutions/SO0111/anonymous_metrics_uuid", Value=old_uuid, Type="String"
    )
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    # ACT
    metrics = Metrics()

    # ASSERT
    assert metrics.solution_uuid == old_uuid
    assert metrics.solution_version == "v1.2.0TEST"

    # Verify migration occurred
    with pytest.raises(ssm.exceptions.ParameterNotFound):
        ssm.get_parameter(Name="/Solutions/SO0111/anonymous_metrics_uuid")

    response = ssm.get_parameter(Name="/Solutions/SO0111/metrics_uuid")
    assert response["Parameter"]["Value"] == old_uuid


@mock_aws
def test_metrics_construction_version_not_found():
    """Test metrics construction when version parameter doesn't exist"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/metrics_uuid",
        Value="11111111-1111-1111-1111-111111111111",
        Type="String",
    )

    # ACT
    metrics = Metrics()

    # ASSERT
    assert metrics.solution_uuid == "11111111-1111-1111-1111-111111111111"
    assert metrics.solution_version == "unknown"


@mock_aws
def test_metrics_construction_version_access_denied():
    """Test metrics construction when version parameter access fails"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/metrics_uuid",
        Value="11111111-1111-1111-1111-111111111111",
        Type="String",
    )

    with patch("boto3.session.Session") as mock_session:
        mock_session.return_value.region_name = get_region()

        with patch("layer.awsapi_cached_client.AWSCachedClient") as mock_client:
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.side_effect = [
                {
                    "Parameter": {"Value": "11111111-1111-1111-1111-111111111111"}
                },  # UUID call
                ClientError(
                    {"Error": {"Code": "AccessDenied"}}, "GetParameter"
                ),  # Version call
            ]
            mock_client.return_value.get_connection.return_value = mock_ssm

            # ACT
            metrics = Metrics()

            # ASSERT
            assert metrics.solution_uuid == "11111111-1111-1111-1111-111111111111"
            assert metrics.solution_version == "unknown"


@mock_aws
def test_metrics_construction_ssm_connection_failure():
    """Test metrics construction when SSM connection fails"""
    # ARRANGE
    with patch("layer.awsapi_cached_client.AWSCachedClient") as mock_client:
        mock_client.side_effect = Exception("Connection failed")

        # ACT
        metrics = Metrics()

        # ASSERT (an exception should not be raised)
        assert metrics.ssm_client is None


@mock_aws
def test_metrics_construction_uuid_parameter_creation_failure():
    """Test metrics construction when UUID parameter creation fails"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    with patch("boto3.session.Session") as mock_session:
        mock_session.return_value.region_name = get_region()

        with patch("layer.awsapi_cached_client.AWSCachedClient") as mock_client:
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.side_effect = [
                ClientError(
                    {"Error": {"Code": "ParameterNotFound"}}, "GetParameter"
                ),  # UUID call
                ClientError(
                    {"Error": {"Code": "ParameterNotFound"}}, "GetParameter"
                ),  # Old UUID call
                {"Parameter": {"Value": "v1.2.0TEST"}},  # Version call
            ]
            mock_ssm.put_parameter.side_effect = Exception("Access denied")
            mock_client.return_value.get_connection.return_value = mock_ssm

            # ACT
            metrics = Metrics()

            # ASSERT
            assert metrics.solution_uuid == "unknown"
            assert metrics.solution_version == "v1.2.0TEST"


@mock_aws
def test_metrics_construction_general_uuid_exception():
    """Test metrics construction when UUID retrieval has general exception"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    with patch("boto3.session.Session") as mock_session:
        mock_session.return_value.region_name = get_region()

        with patch("layer.awsapi_cached_client.AWSCachedClient") as mock_client:
            mock_ssm = MagicMock()
            mock_ssm.get_parameter.side_effect = [
                Exception("General error"),  # UUID call
                {"Parameter": {"Value": "v1.2.0TEST"}},  # Version call
            ]
            mock_client.return_value.get_connection.return_value = mock_ssm

            # ACT
            metrics = Metrics()

            # ASSERT
            assert metrics.solution_uuid == "unknown"
            assert metrics.solution_version == "v1.2.0TEST"


@mock_aws
def test_get_metrics_from_event_with_finding():
    """Test extracting metrics from event with finding"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    metrics = Metrics()
    event = {
        "Finding": {
            "GeneratorId": "test-generator",
            "Title": "Test Finding",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        },
        "EventType": "unit-test",
        "CustomActionName": "TestAction",
    }

    # ACT
    result = metrics.get_metrics_from_event(event)

    # ASSERT
    expected = {
        "generator_id": "test-generator",
        "type": "Test Finding",
        "productArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "finding_triggered_by": "unit-test",
        "region": get_region(),
        "custom_action_name": "TestAction",
    }
    assert result == expected


@mock_aws
def test_get_metrics_from_event_without_finding():
    """Test extracting metrics from event without finding"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    metrics = Metrics()
    event = {"EventType": "unit-test"}

    # ACT
    result = metrics.get_metrics_from_event(event)

    # ASSERT
    assert result == {}


@mock_aws
def test_send_metrics_with_data():
    """Test sending metrics with valid data"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/metrics_uuid",
        Value="11111111-1111-1111-1111-111111111111",
        Type="String",
    )
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    metrics = Metrics()
    metrics_data = {"test": "data"}

    with patch.object(metrics, "post_metrics_to_api") as mock_post:
        # ACT
        metrics.send_metrics(metrics_data)

        # ASSERT
        mock_post.assert_called_once()
        call_args = mock_post.call_args[0][0]
        assert call_args["Solution"] == "SO0111"
        assert call_args["UUID"] == "11111111-1111-1111-1111-111111111111"
        assert call_args["AccountId"] == MOCK_ACCOUNT_ID
        assert call_args["StackId"] == MOCK_STACK_ID
        assert call_args["Data"] == metrics_data
        assert call_args["Version"] == "v1.2.0TEST"
        assert "TimeStamp" in call_args


@mock_aws
def test_send_metrics_with_none_data():
    """Test sending metrics with None data"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    metrics = Metrics()

    with patch.object(metrics, "post_metrics_to_api") as mock_post:
        # ACT
        metrics.send_metrics(None)

        # ASSERT
        mock_post.assert_not_called()


@mock_aws
def test_send_metrics_exception():
    """Test send_metrics handles exceptions"""
    # ARRANGE
    ssm = boto3.client("ssm", region_name=get_region())
    ssm.put_parameter(
        Name="/Solutions/SO0111/version", Value="v1.2.0TEST", Type="String"
    )

    metrics = Metrics()
    metrics_data = {"test": "data"}

    with patch.object(
        metrics, "post_metrics_to_api", side_effect=Exception("Test error")
    ):
        # ACT (should not raise exception)
        metrics.send_metrics(metrics_data)


def test_post_metrics_to_api_success():
    """Test successful API call"""
    # ARRANGE
    metrics = Metrics()
    request_data = {"test": "data"}

    with patch("layer.metrics.urlopen") as mock_urlopen, patch(
        "layer.metrics.Request"
    ) as mock_request:

        # ACT
        metrics.post_metrics_to_api(request_data)

        # ASSERT
        expected_url = "https://metrics.awssolutionsbuilder.com/generic"
        expected_data = bytes(
            urllib.parse.quote(json.dumps(request_data)), encoding="utf8"
        )
        expected_headers = {"Content-Type": "application/json"}

        mock_request.assert_called_once_with(
            expected_url, method="POST", data=expected_data, headers=expected_headers
        )
        mock_urlopen.assert_called_once()


def test_post_metrics_to_api_http_error():
    """Test post_metrics_to_api handling of HTTPError"""
    # ARRANGE
    metrics = Metrics()
    mock_data = {"Solution": "SO0111", "UUID": "test-uuid", "Data": {}}

    with patch("layer.metrics.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = HTTPError(
            url="test_url", code=404, msg="Not Found", hdrs={}, fp=None  # type: ignore
        )

        # ACT & ASSERT
        with pytest.raises(HTTPError):
            metrics.post_metrics_to_api(mock_data)


def test_post_metrics_to_api_url_error():
    """Test post_metrics_to_api handling of URLError"""
    # ARRANGE
    metrics = Metrics()
    mock_data = {"Solution": "SO0111", "UUID": "test-uuid", "Data": {}}

    with patch("layer.metrics.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = URLError("Test URL Error")

        # ACT & ASSERT
        with pytest.raises(URLError):
            metrics.post_metrics_to_api(mock_data)


def test_get_status_for_metrics_success():
    """Test successful status normalization"""
    # ACT & ASSERT
    status, reason = Metrics.get_status_for_metrics("SUCCESS")
    assert status == "SUCCESS"
    assert reason == ""

    # Test case insensitivity
    status, reason = Metrics.get_status_for_metrics("success")
    assert status == "SUCCESS"
    assert reason == ""


def test_get_status_for_metrics_queued():
    """Test queued status normalization"""
    # ACT & ASSERT
    status, reason = Metrics.get_status_for_metrics("QUEUED")
    assert status == "PENDING"
    assert reason == ""

    # Test case insensitivity
    status, reason = Metrics.get_status_for_metrics("queued")
    assert status == "PENDING"
    assert reason == ""


def test_get_status_for_metrics_failed_cases():
    """Test various failure cases and their reason mappings"""
    # ARRANGE
    test_cases = [
        ("FAILED", "REMEDIATION_FAILED"),
        ("LAMBDA_ERROR", "ORCHESTRATOR_FAILED"),
        ("RUNBOOK_NOT_ACTIVE", "RUNBOOK_NOT_ACTIVE"),
        ("PLAYBOOK_NOT_ENABLED", "PLAYBOOK_NOT_ENABLED"),
        ("TIMEDOUT", "REMEDIATION_TIMED_OUT"),
        ("CANCELLED", "REMEDIATION_CANCELLED"),
        ("CANCELLING", "REMEDIATION_CANCELLED"),
        ("ASSUME_ROLE_FAILURE", "ACCOUNT_NOT_ONBOARDED"),
        ("NO_RUNBOOK", "NO_REMEDIATION_AVAILABLE"),
        ("NOT_NEW", "FINDING_WORKFLOW_STATE_NOT_NEW"),
    ]

    for input_status, expected_reason in test_cases:
        # ACT & ASSERT
        status, reason = Metrics.get_status_for_metrics(input_status)
        assert status == "FAILED"
        assert reason == expected_reason

        # Test case insensitivity
        status, reason = Metrics.get_status_for_metrics(input_status.lower())
        assert status == "FAILED"
        assert reason == expected_reason


def test_get_status_for_metrics_unknown_failure():
    """Test handling of unknown failure status"""
    # ACT & ASSERT
    status, reason = Metrics.get_status_for_metrics("UNKNOWN_STATUS")
    assert status == "FAILED"
    assert reason == "UNKNOWN"
