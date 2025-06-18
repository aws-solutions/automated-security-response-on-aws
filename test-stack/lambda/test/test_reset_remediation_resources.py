# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

import boto3
from botocore.config import Config
from moto import mock_aws
from reset_remediation_resources import lambda_handler

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=REGION)

TEST_BUCKET = "test-bucket-name"
TEST_KEY = "my_key"
TEST_QUEUE = "my_queue"


def setup(controls):
    # Create resources for each specified control
    result = {}
    if "S3.9" in controls:
        s3_client = boto3.client("s3", config=BOTO_CONFIG)
        s3_client.create_bucket(
            Bucket=TEST_BUCKET,
        )
        result["bucket_name"] = TEST_BUCKET
    if "KMS.4" in controls:
        kms_client = boto3.client("kms", config=BOTO_CONFIG)
        response = kms_client.create_key(
            KeySpec="RSA_4096",
            KeyUsage="ENCRYPT_DECRYPT",
        )
        kms_client.enable_key_rotation(KeyId=response["KeyMetadata"]["KeyId"])

        result["key_id"] = response["KeyMetadata"]["KeyId"]
    if "SecretsManager.1" in controls:
        secrets_client = boto3.client("secretsmanager", config=BOTO_CONFIG)
        secrets_client.create_secret(
            Name=TEST_KEY,
            SecretString='{"username":"example","password":"EXAMPLE-PASSWORD"}',
        )
        secrets_client.rotate_secret(
            RotationLambdaARN=create_lambda(),
            RotationRules={
                "Duration": "2h",
                "ScheduleExpression": "cron(0 16 1,15 * ? *)",
            },
            SecretId=TEST_KEY,
        )

        result["secret_name"] = TEST_KEY
    if "SQS.1" in controls:
        sqs_client = boto3.client("sqs", config=BOTO_CONFIG)
        response = sqs_client.create_queue(
            QueueName=TEST_QUEUE,
            Attributes={"KmsMasterKeyId": "alias/aws/sqs"},
        )
        result["queue_url"] = response["QueueUrl"]
    return result


def create_lambda():
    iam_client = boto3.client("iam", config=BOTO_CONFIG)
    iam_response = iam_client.create_role(
        AssumeRolePolicyDocument="<Stringified-JSON>",
        Path="/",
        RoleName="Test-Role",
    )

    lambda_client = boto3.client("lambda", config=BOTO_CONFIG)
    lambda_response = lambda_client.create_function(
        Code={
            "ZipFile": b"my-code",
        },
        FunctionName="my-function",
        Handler="index.handler",
        Role=iam_response["Role"]["Arn"],
        Runtime="nodejs12.x",
    )
    return lambda_response["FunctionArn"]


def verify_key_rotation_disabled(key_id):
    kms_client = boto3.client("kms", config=BOTO_CONFIG)

    response = kms_client.get_key_rotation_status(KeyId=key_id)
    assert not response["KeyRotationEnabled"]


def verify_secret_rotation_disabled(secret_id):
    secrets_client = boto3.client("secretsmanager", config=BOTO_CONFIG)

    response = secrets_client.describe_secret(SecretId=secret_id)
    assert not response["RotationEnabled"]


def verify_queue_encryption_disabled(queue_url):
    sqs_client = boto3.client("sqs", config=BOTO_CONFIG)

    response = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["KmsMasterKeyId"]
    )
    if "Attributes" in response:
        assert not response["Attributes"]["KmsMasterKeyId"]


def verify_server_access_logging_disabled(bucket_name):
    s3_client = boto3.client("s3", config=BOTO_CONFIG)

    response = s3_client.get_bucket_logging(
        Bucket=bucket_name,
    )
    if "LoggingEnabled" in response:
        assert not response["LoggingEnabled"]


@mock_aws(config={"lambda": {"use_docker": False}})
def test_handler():
    test_controls = ["S3.9", "KMS.4", "SecretsManager.1", "SQS.1"]
    result = setup(test_controls)
    os.environ["BucketName"] = result["bucket_name"]
    os.environ["KMSKeyId"] = result["key_id"]
    os.environ["SecretId"] = result["secret_name"]
    os.environ["QueueURL"] = result["queue_url"]

    response = lambda_handler({}, None)

    assert not response["FailedResources"]
    verify_key_rotation_disabled(result["key_id"])
    verify_queue_encryption_disabled(result["queue_url"])
    verify_secret_rotation_disabled(result["secret_name"])
    verify_server_access_logging_disabled(result["bucket_name"])


@mock_aws
def test_handler_with_nonexistent_resources():
    os.environ["BucketName"] = "some-bucket"
    os.environ["KMSKeyId"] = "some-key"
    os.environ["SecretId"] = "some-secret"
    os.environ["QueueURL"] = "some-queue-url"

    response = lambda_handler({}, None)

    assert len(response["FailedResources"]) == 4
