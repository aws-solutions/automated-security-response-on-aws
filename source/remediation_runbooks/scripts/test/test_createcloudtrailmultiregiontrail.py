# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from typing import TYPE_CHECKING, Any, Dict

import boto3
import botocore.session
import CreateCloudTrailMultiRegionTrail_createcloudtrailbucket as createcloudtrailbucket
import CreateCloudTrailMultiRegionTrail_createcloudtrailbucketpolicy as createcloudtrailbucketpolicy
import CreateCloudTrailMultiRegionTrail_createloggingbucket as createloggingbucket
import CreateCloudTrailMultiRegionTrail_enablecloudtrail as enablecloudtrail
import CreateCloudTrailMultiRegionTrail_process_results as process_results
import pytest
from aws_lambda_powertools.utilities.typing import LambdaContext
from botocore.config import Config
from botocore.stub import Stubber
from CreateCloudTrailMultiRegionTrail_createloggingbucket import Event
from moto import mock_aws

if TYPE_CHECKING:
    from mypy_boto3_s3.client import S3Client
else:
    S3Client = object


def get_region() -> str:
    my_session = boto3.session.Session()
    return my_session.region_name


# =====================================================================================
# CreateCloudTrailMultiRegionTrail_createcloudtrailbucket
# =====================================================================================
@mock_aws
def test_create_encrypted_bucket():
    # ARRANGE
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": "us-east-1",
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "account": "111111111111",
        "logging_bucket": "mah-loggin-bukkit",
    }
    bucket_name = "so0111-aws-cloudtrail-111111111111"

    # Create the logging bucket first with proper ACL for S3 log delivery
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=event["logging_bucket"])
    s3.put_bucket_acl(
        Bucket=event["logging_bucket"],
        GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
    )

    # ACT
    result = createcloudtrailbucket.create_encrypted_bucket(event, {})

    # ASSERT
    assert result["cloudtrail_bucket"] == bucket_name
    assert result["ResourceArn"] == f"arn:aws:s3:::{bucket_name}"

    # Verify bucket was created with correct configuration
    buckets = s3.list_buckets()
    bucket_names = [b["Name"] for b in buckets["Buckets"]]
    assert bucket_name in bucket_names

    # Check encryption is configured
    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
    assert (
        encryption["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "aws:kms"
    )

    # Check public access block is configured
    public_access = s3.get_public_access_block(Bucket=bucket_name)
    assert public_access["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
    assert public_access["PublicAccessBlockConfiguration"]["IgnorePublicAcls"] is True


def test_bucket_already_exists(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "account": "111111111111",
        "logging_bucket": "mah-loggin-bukkit",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs: Dict[str, Any] = {
        "Bucket": "so0111-aws-cloudtrail-111111111111",
        "ACL": "private",
    }
    if get_region() != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": get_region()}

    s3_stubber.add_client_error("create_bucket", "BucketAlreadyExists")

    s3_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_createcloudtrailbucket.connect_to_s3",
        return_value=s3,
    )
    with pytest.raises(SystemExit):
        createcloudtrailbucket.create_encrypted_bucket(event, {})
    s3_stubber.deactivate()


@mock_aws
def test_bucket_already_owned_by_you():
    # ARRANGE
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": "us-east-1",
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "account": "111111111111",
        "logging_bucket": "mah-loggin-bukkit",
    }
    bucket_name = "so0111-aws-cloudtrail-111111111111"

    # Create both buckets to simulate "already owned by you" scenario
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=event["logging_bucket"])
    s3.put_bucket_acl(
        Bucket=event["logging_bucket"],
        GrantWrite="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
        GrantReadACP="uri=http://acs.amazonaws.com/groups/s3/LogDelivery",
    )
    s3.create_bucket(Bucket=bucket_name)

    # ACT
    result = createcloudtrailbucket.create_encrypted_bucket(event, {})

    # ASSERT
    assert result == {
        "cloudtrail_bucket": bucket_name,
        "ResourceArn": f"arn:aws:s3:::{bucket_name}",
    }


# =====================================================================================
# CreateCloudTrailMultiRegionTrail_createcloudtrailbucketpolicy
# =====================================================================================
def test_create_bucket_policy(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "partition": "aws",
        "account": "111111111111",
        "cloudtrail_bucket": "mahbukkit",
    }
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck20150319",
                "Effect": "Allow",
                "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
                "Action": "s3:GetBucketAcl",
                "Resource": "arn:aws:s3:::mahbukkit",
            },
            {
                "Sid": "AWSCloudTrailWrite20150319",
                "Effect": "Allow",
                "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::mahbukkit/AWSLogs/111111111111/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
            {
                "Sid": "AllowSSLRequestsOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": ["arn:aws:s3:::mahbukkit", "arn:aws:s3:::mahbukkit/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)
    kwargs: Dict[str, Any] = {
        "Bucket": "so0111-aws-cloudtrail-111111111111",
        "ACL": "private",
    }
    if get_region() != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": get_region()}

    s3_stubber.add_response(
        "put_bucket_policy",
        {},
        {"Bucket": "mahbukkit", "Policy": json.dumps(bucket_policy)},
    )

    s3_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_createcloudtrailbucketpolicy.connect_to_s3",
        return_value=s3,
    )
    createcloudtrailbucketpolicy.create_bucket_policy(event, {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


# =====================================================================================
# CreateCloudTrailMultiRegionTrail_createloggingbucket
# =====================================================================================
@mock_aws
def test_create_logging_bucket():
    # ARRANGE
    event: Event = {
        "region": "us-east-1",
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "account": "111111111111",
    }
    bucket_name = "so0111-access-logs-us-east-1-111111111111"

    # ACT
    result = createloggingbucket.create_logging_bucket(event, LambdaContext())

    # ASSERT
    assert result["logging_bucket"] == bucket_name
    assert result["ResourceArn"] == f"arn:aws:s3:::{bucket_name}"

    # Verify bucket was created with correct configuration
    s3 = boto3.client("s3", region_name="us-east-1")

    # Check bucket exists
    buckets = s3.list_buckets()
    bucket_names = [b["Name"] for b in buckets["Buckets"]]
    assert bucket_name in bucket_names

    # Check encryption is configured
    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
    assert (
        encryption["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "aws:kms"
    )

    # Check public access block is configured
    public_access = s3.get_public_access_block(Bucket=bucket_name)
    assert public_access["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
    assert public_access["PublicAccessBlockConfiguration"]["IgnorePublicAcls"] is True


# =====================================================================================
# CreateCloudTrailMultiRegionTrail_enablecloudtrail
# =====================================================================================
def test_enable_cloudtrail(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "cloudtrail_bucket": "mahbukkit",
        "account_id": "111111111111",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )

    ct_stubber = Stubber(ct_client)

    # Add describe_trails response (trail doesn't exist)
    ct_stubber.add_response(
        "describe_trails",
        {"trailList": []},
        {"trailNameList": ["multi-region-cloud-trail"]},
    )

    ct_stubber.add_response(
        "create_trail",
        {},
        {
            "Name": "multi-region-cloud-trail",
            "S3BucketName": "mahbukkit",
            "IncludeGlobalServiceEvents": True,
            "EnableLogFileValidation": True,
            "IsMultiRegionTrail": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        },
    )

    ct_stubber.add_response("start_logging", {}, {"Name": "multi-region-cloud-trail"})

    ct_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail",
        return_value=ct_client,
    )

    result = enablecloudtrail.enable_cloudtrail(event, {})

    assert (
        result["output"]["Message"]
        == "CloudTrail Trail multi-region-cloud-trail created"
    )
    assert "ResourceArn" in result["output"]
    assert result["output"]["ResourceArn"].startswith("arn:aws:cloudtrail:")
    assert "trail/multi-region-cloud-trail" in result["output"]["ResourceArn"]

    ct_stubber.assert_no_pending_responses()
    ct_stubber.deactivate()


def test_enable_cloudtrail_trail_exists(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "cloudtrail_bucket": "mahbukkit",
        "account_id": "111111111111",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )

    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        "describe_trails",
        {"trailList": [{"Name": "multi-region-cloud-trail"}]},
        {"trailNameList": ["multi-region-cloud-trail"]},
    )

    ct_stubber.add_response(
        "update_trail",
        {},
        {
            "Name": "multi-region-cloud-trail",
            "S3BucketName": "mahbukkit",
            "IncludeGlobalServiceEvents": True,
            "EnableLogFileValidation": True,
            "IsMultiRegionTrail": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        },
    )

    ct_stubber.add_response("start_logging", {}, {"Name": "multi-region-cloud-trail"})

    ct_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail",
        return_value=ct_client,
    )

    result = enablecloudtrail.enable_cloudtrail(event, {})

    assert (
        result["output"]["Message"]
        == "CloudTrail Trail multi-region-cloud-trail updated"
    )
    assert "ResourceArn" in result["output"]
    assert result["output"]["ResourceArn"].startswith("arn:aws:cloudtrail:")
    assert "trail/multi-region-cloud-trail" in result["output"]["ResourceArn"]

    ct_stubber.assert_no_pending_responses()
    ct_stubber.deactivate()


def test_enable_cloudtrail_trail_already_exists_exception(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "cloudtrail_bucket": "mahbukkit",
        "account_id": "111111111111",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )

    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        "describe_trails",
        {"trailList": []},
        {"trailNameList": ["multi-region-cloud-trail"]},
    )

    ct_stubber.add_client_error("create_trail", "TrailAlreadyExistsException")

    ct_stubber.add_response(
        "update_trail",
        {},
        {
            "Name": "multi-region-cloud-trail",
            "S3BucketName": "mahbukkit",
            "IncludeGlobalServiceEvents": True,
            "EnableLogFileValidation": True,
            "IsMultiRegionTrail": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        },
    )

    ct_stubber.add_response("start_logging", {}, {"Name": "multi-region-cloud-trail"})

    ct_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail",
        return_value=ct_client,
    )

    result = enablecloudtrail.enable_cloudtrail(event, {})

    assert (
        result["output"]["Message"]
        == "CloudTrail Trail multi-region-cloud-trail updated"
    )
    assert "ResourceArn" in result["output"]
    assert result["output"]["ResourceArn"].startswith("arn:aws:cloudtrail:")
    assert "trail/multi-region-cloud-trail" in result["output"]["ResourceArn"]

    ct_stubber.assert_no_pending_responses()
    ct_stubber.deactivate()


def test_enable_cloudtrail_update_fails_after_trail_exists_exception(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "cloudtrail_bucket": "mahbukkit",
        "account_id": "111111111111",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )
    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        "describe_trails",
        {"trailList": []},
        {"trailNameList": ["multi-region-cloud-trail"]},
    )

    ct_stubber.add_client_error("create_trail", "TrailAlreadyExistsException")

    ct_stubber.add_client_error("update_trail", "InvalidParameterException")

    ct_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail",
        return_value=ct_client,
    )
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        enablecloudtrail.enable_cloudtrail(event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert "Error updating CloudTrail trail" in str(pytest_wrapped_e.value.code)
    ct_stubber.deactivate()


def test_enable_cloudtrail_client_error(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "cloudtrail_bucket": "mahbukkit",
        "account_id": "111111111111",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )
    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        "describe_trails",
        {"trailList": []},
        {"trailNameList": ["multi-region-cloud-trail"]},
    )

    ct_stubber.add_client_error("create_trail", "InsufficientS3BucketPolicyException")

    ct_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail",
        return_value=ct_client,
    )
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        enablecloudtrail.enable_cloudtrail(event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert "Error enabling CloudTrail" in str(pytest_wrapped_e.value.code)
    ct_stubber.deactivate()


def test_enable_cloudtrail_general_exception(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "region": get_region(),
        "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-1234-5678-9012-EXAMPLEKEY",
        "cloudtrail_bucket": "mahbukkit",
        "account_id": "111111111111",
    }
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )
    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        "describe_trails",
        {"trailList": []},
        {"trailNameList": ["multi-region-cloud-trail"]},
    )

    ct_stubber.activate()
    mocker.patch(
        "CreateCloudTrailMultiRegionTrail_enablecloudtrail.connect_to_cloudtrail",
        return_value=ct_client,
    )

    mocker.patch.object(
        ct_client, "create_trail", side_effect=Exception("Unexpected error")
    )

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        enablecloudtrail.enable_cloudtrail(event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert "Error enabling CloudTrail" in str(pytest_wrapped_e.value.code)
    ct_stubber.deactivate()


def test_connect_to_cloudtrail():
    boto_config = Config(retries={"mode": "standard"})
    client = enablecloudtrail.connect_to_cloudtrail(boto_config)
    assert client is not None
    assert client._service_model.service_name == "cloudtrail"


# =====================================================================================
# CreateCloudTrailMultiRegionTrail_process_results
# =====================================================================================
def test_process_results():
    event = {
        "cloudtrail_bucket": "cloudtrail_logs_bucket",
        "logging_bucket": "access_logs_bucket",
    }
    assert process_results.process_results(event, {}) == {
        "response": {
            "message": "AWS CloudTrail successfully enabled",
            "status": "Success",
        }
    }


# =====================================================================================
# Test inputs
# =====================================================================================
def test_put_bucket_acl_fails():
    """
    Verify proper exit when put_bucket_acl fails
    """

    s3: S3Client = boto3.client("s3")
    s3_stubber = Stubber(s3)
    s3_stubber.add_client_error("put_bucket_acl", "ADoorIsAjar")
    s3_stubber.activate()

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        createloggingbucket.put_bucket_acl(s3, "mahbukkit")
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "Error setting ACL for bucket mahbukkit: An error occurred (ADoorIsAjar) when calling the PutBucketAcl operation: "
    )

    s3_stubber.deactivate()


def test_put_access_blocks_fails():
    """
    Verify proper exit when put_public_access_blocks fails
    """

    s3: S3Client = boto3.client("s3")
    s3_stubber = Stubber(s3)
    s3_stubber.add_client_error("put_public_access_block", "ADoorIsAjar")
    s3_stubber.activate()

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        createloggingbucket.put_access_block(s3, "mahbukkit")
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "Error setting public access block for bucket mahbukkit: An error occurred (ADoorIsAjar) when calling the PutPublicAccessBlock operation: "
    )

    s3_stubber.deactivate()


def test_encrypt_bucket_fails():
    """
    Verify proper exit when put_bucket_encryption fails
    """

    s3: S3Client = boto3.client("s3")
    s3_stubber = Stubber(s3)
    s3_stubber.add_client_error("put_bucket_encryption", "ADoorIsAjar")
    s3_stubber.activate()

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        createloggingbucket.encrypt_bucket(
            s3, "mahbukkit", "arn:aws:kms:us-east-1:111111111111:key/EXAMPLE-KEY-ID"
        )
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "Error encrypting bucket mahbukkit: An error occurred (ADoorIsAjar) when calling the PutBucketEncryption operation: "
    )

    s3_stubber.deactivate()
