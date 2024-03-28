# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import ANY, MagicMock, patch

from layer.awsapi_cached_client import AWSCachedClient, BotoSession


def test_create_client():
    AWS = AWSCachedClient("us-east-1")

    AWS.get_connection("sns")  # in us-east-1
    my_account = AWS.account
    assert my_account
    assert "sns" in AWS.client
    assert "us-east-1" in AWS.client["sns"]
    AWS.get_connection("ec2")
    assert "ec2" in AWS.client
    assert "us-east-1" in AWS.client["ec2"]
    AWS.get_connection("iam", "ap-northeast-1")
    assert "iam" in AWS.client
    assert "ap-northeast-1" in AWS.client["iam"]


@patch("layer.awsapi_cached_client.Session")
def test_boto_session_uses_regional_sts_endpoint(mock_session: MagicMock) -> None:
    mock_client = MagicMock()
    mock_session.return_value.client = mock_client
    region_name = "executing-region"
    mock_session.return_value.region_name = region_name

    BotoSession(role="SO0111-SHARR-Orchestrator-Member")

    mock_client.assert_called_with(
        "sts",
        region_name=region_name,
        endpoint_url=f"https://sts.{region_name}.amazonaws.com",
        config=ANY,
    )
