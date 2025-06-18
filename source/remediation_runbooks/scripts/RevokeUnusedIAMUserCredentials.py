# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone
from typing import Optional, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard"})


def connect_to_service(service):
    return boto3.client(service, config=boto_config)


class Event(TypedDict):
    IAMResourceId: str
    MaxCredentialUsageAge: str


class HandlerResponse(TypedDict):
    Message: str
    Status: str
    DeactivatedKeys: str
    DeletedProfile: Optional[str]


class LoginProfile(TypedDict):
    UserName: str
    CreateDate: datetime
    PasswordResetRequired: bool


def handler(event, _) -> HandlerResponse:
    try:
        iam_resource_id = event.get("IAMResourceId")
        user_name = get_user_name(iam_resource_id)

        max_credential_usage_age = int(event.get("MaxCredentialUsageAge"))

        access_keys = list_access_keys(user_name)
        deactivated_keys = deactivate_unused_keys(
            access_keys, max_credential_usage_age, user_name
        )

        deleted_profile = delete_unused_password(user_name, max_credential_usage_age)

        return {
            "Message": "Successfully revoked unused IAM user credentials",
            "Status": "Success",
            "DeactivatedKeys": str(deactivated_keys),
            "DeletedProfile": deleted_profile,
        }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error while revoking unusued IAM user credentials: {str(e)}"
        )


def list_access_keys(user_name: str) -> list:
    iam_client = connect_to_service("iam")
    try:
        paginator = iam_client.get_paginator("list_access_keys")
        access_keys = []

        for page in paginator.paginate(UserName=user_name):
            access_keys.extend(page.get("AccessKeyMetadata", []))

        return access_keys
    except Exception as e:
        raise RuntimeError(
            f"Encountered error listing access keys for user {user_name}: {str(e)}"
        )


def deactivate_key(user_name: str, access_key: str) -> Optional[str]:
    iam_client = connect_to_service("iam")
    try:
        iam_client.update_access_key(
            UserName=user_name, AccessKeyId=access_key, Status="Inactive"
        ),
        return access_key
    except ClientError:
        return None
    except Exception as e:
        raise RuntimeError(
            f"Encountered error deactivating access key {access_key} for user {user_name}: {str(e)}"
        )


def deactivate_unused_keys(
    access_keys: list, max_credential_usage_age: int, user_name: str
) -> list[str]:
    iam_client = connect_to_service("iam")
    try:
        deactivated_keys = []
        for key in access_keys:
            last_used = iam_client.get_access_key_last_used(
                AccessKeyId=key.get("AccessKeyId")
            ).get("AccessKeyLastUsed")
            if last_used.get("LastUsedDate"):
                last_used_date = last_used.get("LastUsedDate")
                days_since_last_used = (
                    datetime.now(timezone.utc) - last_used_date
                ).days
                if days_since_last_used >= max_credential_usage_age:
                    deactivated_keys.append(
                        deactivate_key(user_name, key.get("AccessKeyId"))
                    )
            else:
                create_date = key.get("CreateDate")
                days_since_creation = (datetime.now(timezone.utc) - create_date).days
                if days_since_creation >= max_credential_usage_age:
                    deactivated_keys.append(
                        deactivate_key(user_name, key.get("AccessKeyId"))
                    )
        return [key for key in deactivated_keys if key]
    except Exception as e:
        raise RuntimeError(
            f"Encountered error deactivating unused access keys: {str(e)}"
        )


def get_login_profile(user_name: str) -> Optional[LoginProfile]:
    iam_client = connect_to_service("iam")
    try:
        return iam_client.get_login_profile(UserName=user_name)["LoginProfile"]
    except iam_client.exceptions.NoSuchEntityException:
        return None


def delete_unused_password(
    user_name: str, max_credential_usage_age: int
) -> Optional[str]:
    iam_client = connect_to_service("iam")
    try:
        user = iam_client.get_user(UserName=user_name).get("User")

        days_since_password_last_used = 0
        login_profile = get_login_profile(user_name)

        if login_profile and user.get("PasswordLastUsed"):
            password_last_used = user.get("PasswordLastUsed")
            days_since_password_last_used = (
                datetime.now(timezone.utc) - password_last_used
            ).days
        elif login_profile and not user.get("PasswordLastUsed"):
            password_creation_date = login_profile.get("CreateDate")
            days_since_password_last_used = (
                datetime.now(timezone.utc) - password_creation_date
            ).days
        if days_since_password_last_used >= max_credential_usage_age:
            iam_client.delete_login_profile(UserName=user_name)
            return user_name
    except Exception as e:
        raise RuntimeError(
            f"Encountered error deleting unused password for user {user_name}: {str(e)}"
        )


def get_user_name(resource_id: str) -> str:
    config_client = connect_to_service("config")
    try:
        list_discovered_resources_response = config_client.list_discovered_resources(
            resourceType="AWS::IAM::User", resourceIds=[resource_id]
        )
        resource_name = list_discovered_resources_response.get("resourceIdentifiers")[
            0
        ].get("resourceName")
        return resource_name
    except Exception as e:
        raise RuntimeError(
            f"Encountered error fetching user name for resource {resource_id}: {str(e)}"
        )
