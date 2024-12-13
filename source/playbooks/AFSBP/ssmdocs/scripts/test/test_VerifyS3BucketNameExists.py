# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import pytest
import VerifyS3BucketNameExists as remediation
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def setup():
    ssm_client = boto3.client("ssm", config=BOTO_CONFIG)
    ssm_client.put_parameter(
        Name="/Solutions/SO0111/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging",
        Value="my-bucket",
        Type="String",
    )


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch("VerifyS3BucketNameExists.connect_to_service", return_value=client)
    return stubber


@mock_aws
def test_verify_s3_bucket_name_exists():
    setup()

    response = remediation.verify_s3_bucket_name_exists({}, None)

    assert response["s3_bucket_name_for_redshift_audit_logging"] == "my-bucket"


@mock_aws
def test_verify_s3_bucket_name_exists_without_param():
    response = remediation.verify_s3_bucket_name_exists({}, None)

    assert response["s3_bucket_name_for_redshift_audit_logging"] == "NOT_AVAILABLE"


def test_verify_s3_bucket_name_exists_with_client_error(mocker):
    stubber = setup_client_stubber("ssm", "get_parameter", mocker)
    stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.verify_s3_bucket_name_exists(
            {},
            None,
        )
    assert re.match(r"Encountered error fetching SSM parameter", str(e.value))
    stubber.deactivate()
