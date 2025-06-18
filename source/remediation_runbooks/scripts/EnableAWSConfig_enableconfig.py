# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import logging
import traceback
from typing import Any, TypedDict

import boto3
from botocore.config import Config

logger = logging.getLogger()

DEFAULT_CHANNEL_NAME = DEFAULT_RECORDER_NAME = "default"

boto_config = Config(retries={"mode": "standard"})


class Event(TypedDict):
    account: str
    partition: str
    aws_service_role: str
    config_bucket: str
    topic_arn: str


class Response(TypedDict):
    Message: str


class ExistingRecorderDetails(TypedDict):
    name: str
    recording: bool


def connect_to_config() -> Any:
    return boto3.client("config", config=boto_config)


def enable_config(event: Event, _: Any):
    aws_account = event["account"]
    aws_partition = event["partition"]
    aws_service_role = event["aws_service_role"]
    config_bucket = event["config_bucket"]
    topic_arn = event["topic_arn"]

    existing_recorder_details = get_existing_config_recorder()
    existing_recorder = existing_recorder_details["name"]
    existing_recorder_is_recording = existing_recorder_details["recording"]

    create_or_update_config_recorder(
        aws_partition, aws_account, aws_service_role, existing_recorder
    )

    if not has_existing_delivery_channel():
        create_delivery_channel(config_bucket, aws_account, topic_arn)

    if (not existing_recorder) or (
        existing_recorder and not existing_recorder_is_recording
    ):
        start_recorder(existing_recorder)

    return {
        "Message": f"Successfully completed setting up recorder {existing_recorder or DEFAULT_RECORDER_NAME}"
    }


def get_existing_config_recorder() -> ExistingRecorderDetails:
    config_client = connect_to_config()
    try:
        recorder_name = ""
        recording = False
        describe_recorder_response = config_client.describe_configuration_recorders()
        if (
            describe_recorder_response
            and "ConfigurationRecorders" in describe_recorder_response
        ):
            recorder_name = describe_recorder_response["ConfigurationRecorders"][0][
                "name"
            ]  # there is only ever 1 configuration recorder per account per region

        if recorder_name:
            describe_recorder_status_response = (
                config_client.describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[
                        recorder_name,
                    ]
                )
            )
            recording = (
                describe_recorder_status_response["ConfigurationRecordersStatus"][0][
                    "recording"
                ]
                if "ConfigurationRecordersStatus" in describe_recorder_response
                else False
            )

        return {"name": recorder_name, "recording": recording}
    except Exception as e:
        logger.warning(
            f"Encountered an error fetching existing Config Recorder - continuing to create a new recorder: {str(e)} \n\n {traceback.format_exc()}"
        )
        return {"name": "", "recording": False}


def create_or_update_config_recorder(
    aws_partition: str,
    aws_account: str,
    aws_service_role: str,
    recorder_name: str,
) -> None:
    if not recorder_name:
        recorder_name = DEFAULT_RECORDER_NAME

    config_client = connect_to_config()
    try:
        config_service_role_arn = (
            "arn:"
            + aws_partition
            + ":iam::"
            + aws_account
            + ":role/"
            + aws_service_role
        )
        config_client.put_configuration_recorder(
            ConfigurationRecorder={
                "name": recorder_name,
                "roleARN": config_service_role_arn,
                "recordingGroup": {
                    "allSupported": True,
                    "includeGlobalResourceTypes": True,
                },
            }
        )
    except Exception as e:
        raise RuntimeError(
            f"Encountered an error putting {recorder_name} config recorder: {str(e)} \n\n{traceback.format_exc()}"
        )


def has_existing_delivery_channel() -> bool:
    config_client = connect_to_config()
    try:
        response = config_client.describe_delivery_channels()
        if response and "DeliveryChannels" in response:
            return (
                len(response["DeliveryChannels"]) > 0
            )  # there is only ever one delivery channel per account per region
        return False
    except Exception as e:
        logger.warning(
            f"Encountered an error fetching existing delivery channel - continuing to create a new channel: {str(e)} \n\n {traceback.format_exc()}"
        )
        return False


def create_delivery_channel(
    config_bucket: str, aws_account: str, topic_arn: str
) -> None:
    config_client = connect_to_config()
    try:
        config_client.put_delivery_channel(
            DeliveryChannel={
                "name": DEFAULT_CHANNEL_NAME,
                "s3BucketName": config_bucket,
                "s3KeyPrefix": aws_account,
                "snsTopicARN": topic_arn,
                "configSnapshotDeliveryProperties": {
                    "deliveryFrequency": "Twelve_Hours"
                },
            }
        )
    except Exception as e:
        raise RuntimeError(
            f"Encountered an error creating delivery channel 'default': {str(e)} \n\n{traceback.format_exc()}"
        )


def start_recorder(recorder_name: str) -> None:
    if not recorder_name:
        recorder_name = DEFAULT_RECORDER_NAME
    config_client = connect_to_config()
    try:
        config_client.start_configuration_recorder(
            ConfigurationRecorderName=recorder_name
        )
    except Exception as e:
        raise RuntimeError(
            f"Encountered an error starting config recorder 'default': {str(e)} \n\n{traceback.format_exc()}"
        )
