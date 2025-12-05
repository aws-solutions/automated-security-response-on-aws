# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config


class EventType(TypedDict):
    account_id: str


boto_config = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_ssm():
    return boto3.client("ssm", config=boto_config)


def lambda_handler(event: EventType, _):
    try:
        account_id = event["account_id"]
        ssm_client = connect_to_ssm()

        current_setting = get_service_setting(ssm_client)

        if current_setting == "Disable":
            return {
                "response": {
                    "message": f"Block public sharing is already enabled for account {account_id}",
                    "status": "NO_CHANGE_REQUIRED",
                    "setting_value": "Disable",
                }
            }

        update_service_setting(ssm_client)

        verify_setting = get_service_setting(ssm_client)

        if verify_setting == "Disable":
            return {
                "response": {
                    "message": f"Successfully enabled block public sharing for account {account_id}",
                    "status": "SUCCESS",
                    "setting_value": "Disable",
                }
            }
        else:
            raise RuntimeError(
                f"Failed to verify setting change. Expected 'Disable', got '{verify_setting}'"
            )

    except Exception as e:
        error_msg = f"Failed to enable block public sharing: {str(e)}"
        print(error_msg)
        raise RuntimeError(error_msg)


def get_service_setting(ssm_client):
    try:
        response = ssm_client.get_service_setting(
            SettingId="/ssm/documents/console/public-sharing-permission"
        )
        return response["ServiceSetting"]["SettingValue"]
    except Exception as e:
        raise RuntimeError(f"Failed to get service setting: {str(e)}")


def update_service_setting(ssm_client):
    try:
        ssm_client.update_service_setting(
            SettingId="/ssm/documents/console/public-sharing-permission",
            SettingValue="Disable",
        )
    except Exception as e:
        raise RuntimeError(f"Failed to update service setting: {str(e)}")
