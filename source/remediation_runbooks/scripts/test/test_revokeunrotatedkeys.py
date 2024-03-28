# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime, timezone

import boto3
import botocore.session
import RevokeUnrotatedKeys as remediation
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)


def str_time_to_datetime(dt_str):
    dt_obj = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return dt_obj


def iam_resource():
    return {
        "resourceIdentifiers": [
            {
                "resourceType": "AWS::IAM::User",
                "resourceId": "AIDACKCEVSQ6C2EXAMPLE",
                "resourceName": "someuser",
            }
        ]
    }


def event():
    return {"IAMResourceId": "AIDACKCEVSQ6C2EXAMPLE", "MaxCredentialUsageAge": "90"}


def access_keys():
    return {
        "AccessKeyMetadata": [
            {
                "UserName": "someuser",
                "Status": "Active",
                "CreateDate": str_time_to_datetime("2015-05-22T14:43:16Z"),
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            },
            {
                "UserName": "someuser",
                "Status": "Active",
                "CreateDate": datetime.now(timezone.utc),
                "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
            },
            {
                "UserName": "someuser",
                "Status": "Inactive",
                "CreateDate": str_time_to_datetime("2017-10-15T15:20:04Z"),
                "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
            },
        ]
    }


def updated_keys():
    return {
        "AccessKeyMetadata": [
            {
                "UserName": "someuser",
                "Status": "Inactive",
                "CreateDate": str_time_to_datetime("2015-05-22T14:43:16Z"),
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            },
            {
                "UserName": "someuser",
                "Status": "Active",
                "CreateDate": datetime.now(timezone.utc),
                "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
            },
            {
                "UserName": "someuser",
                "Status": "Inactive",
                "CreateDate": str_time_to_datetime("2017-10-15T15:20:04Z"),
                "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
            },
        ]
    }


def last_accessed_key(id):
    return {
        "AKIAIOSFODNN7EXAMPLE": {
            "UserName": "someuser",
            "AccessKeyLastUsed": {
                "Region": "N/A",
                "ServiceName": "s3",
                "LastUsedDate": str_time_to_datetime("2016-03-23T19:55:00Z"),
            },
        },
        "AKIAI44QH8DHBEXAMPLE": {
            "UserName": "someuser",
            "AccessKeyLastUsed": {
                "Region": "N/A",
                "ServiceName": "s3",
                "LastUsedDate": datetime.now(timezone.utc),
            },
        },
    }[id]


def successful():
    return {
        "http_responses": {
            "DeactivateUnusedKeysResponse": [
                {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "Response": {
                        "ResponseMetadata": {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}
                    },
                }
            ]
        },
        "output": "Verification of unrotated access keys is successful.",
    }


# =====================================================================================
# SUCCESS
# =====================================================================================
def test_success(mocker):
    # Clients
    cfg_client = botocore.session.get_session().create_client(
        "config", config=BOTO_CONFIG
    )
    cfg_stubber = Stubber(cfg_client)

    cfg_stubber.add_response(
        "list_discovered_resources",
        iam_resource(),
        {"resourceType": "AWS::IAM::User", "resourceIds": ["AIDACKCEVSQ6C2EXAMPLE"]},
    )

    cfg_stubber.activate()

    iam_client = botocore.session.get_session().create_client("iam", config=BOTO_CONFIG)
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_response(
        "list_access_keys", access_keys(), {"UserName": "someuser"}
    )

    iam_stubber.add_response(
        "get_access_key_last_used",
        last_accessed_key("AKIAIOSFODNN7EXAMPLE"),
        {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"},
    )

    iam_stubber.add_response(
        "update_access_key",
        {"ResponseMetadata": {"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}},
        {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "UserName": "someuser",
            "Status": "Inactive",
        },
    )

    iam_stubber.add_response(
        "get_access_key_last_used",
        last_accessed_key("AKIAI44QH8DHBEXAMPLE"),
        {"AccessKeyId": "AKIAI44QH8DHBEXAMPLE"},
    )

    iam_stubber.add_response(
        "list_access_keys", updated_keys(), {"UserName": "someuser"}
    )

    iam_stubber.activate()

    mocker.patch("RevokeUnrotatedKeys.connect_to_config", return_value=cfg_client)
    mocker.patch("RevokeUnrotatedKeys.connect_to_iam", return_value=iam_client)

    assert remediation.unrotated_key_handler(event(), {}) == successful()

    cfg_stubber.deactivate()
    iam_stubber.deactivate()
