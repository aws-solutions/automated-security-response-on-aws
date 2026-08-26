# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.typing import LambdaContext
    from mypy_boto3_sns.client import SNSClient
    from mypy_boto3_ssm.client import SSMClient
else:
    LambdaContext = object
    SNSClient = object
    SSMClient = object

boto_config = Config(retries={"mode": "standard"})


class Event(TypedDict):
    KmsKeyArn: str
    TopicName: str
    Region: str
    AccountId: str


class Output(TypedDict):
    TopicArn: str
    ResourceArn: str
    ParameterArn: str


def connect_to_sns() -> SNSClient:
    return boto3.client("sns", config=boto_config)


def connect_to_ssm() -> SSMClient:
    return boto3.client("ssm", config=boto_config)


def get_partition_from_region(region: str) -> str:
    """Derive AWS partition from region name."""
    if region.startswith("cn-"):
        return "aws-cn"
    elif region.startswith("us-gov"):
        return "aws-us-gov"
    else:
        return "aws"


def create_encrypted_topic(event: Event, _: LambdaContext) -> Output:
    kms_key_arn = event["KmsKeyArn"]
    new_topic = False
    topic_arn = ""
    topic_name = event["TopicName"]
    region = event["Region"]
    account_id = event["AccountId"]
    partition = get_partition_from_region(region)

    try:
        sns = connect_to_sns()
        topic_arn = sns.create_topic(
            Name=topic_name, Attributes={"KmsMasterKeyId": kms_key_arn.split("key/")[1]}
        )["TopicArn"]
        new_topic = True

    except ClientError as client_exception:
        exception_type = client_exception.response["Error"]["Code"]
        if exception_type == "InvalidParameter":
            print(
                f"Topic {topic_name} already exists. This remediation may have been run before."
            )
            print("Ignoring exception - remediation continues.")
            topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
        else:
            exit(f"ERROR: Unhandled client exception: {client_exception}")

    except Exception as e:
        exit(f"ERROR: could not create SNS Topic {topic_name}: {str(e)}")

    parameter_name = "/Solutions/SO0111/SNS_Topic_CIS3.x"
    if new_topic:
        try:
            ssm = connect_to_ssm()
            ssm.put_parameter(
                Name=parameter_name,
                Description="SNS Topic for AWS Config updates",
                Type="String",
                Overwrite=True,
                Value=topic_arn,
            )
        except Exception as e:
            exit(f"ERROR: could not create SSM parameter {parameter_name}: {str(e)}")

    create_topic_policy(topic_arn)

    parameter_arn = (
        f"arn:{partition}:ssm:{region}:{account_id}:parameter{parameter_name}"
    )

    return {
        "TopicArn": topic_arn,
        "ResourceArn": topic_arn,
        "ParameterArn": parameter_arn,
    }


def create_topic_policy(topic_arn: str) -> None:
    sns = connect_to_sns()
    try:
        topic_policy = {
            "Id": "Policy_ID",
            "Statement": [
                {
                    "Sid": "AWSConfigSNSPolicy",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "SNS:Publish",
                    "Resource": topic_arn,
                }
            ],
        }

        sns.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(topic_policy),
        )
    except Exception as e:
        exit(f"ERROR: Failed to SetTopicAttributes for {topic_arn}: {str(e)}")
