# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard"})


def connect_to_sns():
    return boto3.client("sns", config=boto_config)


def connect_to_ssm():
    return boto3.client("ssm", config=boto_config)


def create_encrypted_topic(event, _):
    kms_key_arn = event["kms_key_arn"]
    new_topic = False
    topic_arn = ""
    topic_name = event["topic_name"]

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

    if new_topic:
        try:
            ssm = connect_to_ssm()
            ssm.put_parameter(
                Name="/Solutions/SO0111/SNS_Topic_CIS3.x",
                Description="SNS Topic for AWS Config updates",
                Type="String",
                Overwrite=True,
                Value=topic_arn,
            )
        except Exception as e:
            exit(f"ERROR: could not create SNS Topic {topic_name}: {str(e)}")

    create_topic_policy(topic_arn)

    return {"topic_arn": topic_arn}


def create_topic_policy(topic_arn):
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
