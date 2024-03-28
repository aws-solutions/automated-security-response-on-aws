# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard"})


def connect_to_config(boto_config):
    return boto3.client("config", config=boto_config)


def create_config_recorder(aws_partition, aws_account, aws_service_role):
    cfgsvc = connect_to_config(boto_config)
    try:
        config_service_role_arn = (
            "arn:"
            + aws_partition
            + ":iam::"
            + aws_account
            + ":role/"
            + aws_service_role
        )
        cfgsvc.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": config_service_role_arn,
                "recordingGroup": {
                    "allSupported": True,
                    "includeGlobalResourceTypes": True,
                },
            }
        )
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # recorder already exists - continue
        if exception_type in ["MaxNumberOfConfigurationRecordersExceededException"]:
            print("Config Recorder already exists. Continuing.")
        else:
            exit(
                f"ERROR: Boto3 ClientError enabling Config: {exception_type} - {str(ex)}"
            )
    except Exception as e:
        exit(f"ERROR enabling AWS Config - create_config_recorder: {str(e)}")


def create_delivery_channel(config_bucket, aws_account, topic_arn):
    cfgsvc = connect_to_config(boto_config)
    try:
        cfgsvc.put_delivery_channel(
            DeliveryChannel={
                "name": "default",
                "s3BucketName": config_bucket,
                "s3KeyPrefix": aws_account,
                "snsTopicARN": topic_arn,
                "configSnapshotDeliveryProperties": {
                    "deliveryFrequency": "Twelve_Hours"
                },
            }
        )
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # delivery channel already exists - return
        if exception_type in ["MaxNumberOfDeliveryChannelsExceededException"]:
            print("DeliveryChannel already exists")
        else:
            exit(
                f"ERROR: Boto3 ClientError enabling Config: {exception_type} - {str(ex)}"
            )
    except Exception as e:
        exit(f"ERROR enabling AWS Config - create_delivery_channel: {str(e)}")


def start_recorder():
    cfgsvc = connect_to_config(boto_config)
    try:
        cfgsvc.start_configuration_recorder(ConfigurationRecorderName="default")
    except Exception as e:
        exit(f"ERROR enabling AWS Config: {str(e)}")


def enable_config(event, _):
    aws_account = event["account"]
    aws_partition = event["partition"]
    aws_service_role = event["aws_service_role"]
    config_bucket = event["config_bucket"]
    topic_arn = event["topic_arn"]

    create_config_recorder(aws_partition, aws_account, aws_service_role)
    create_delivery_channel(config_bucket, aws_account, topic_arn)
    start_recorder()
