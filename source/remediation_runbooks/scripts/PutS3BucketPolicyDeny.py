# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Given a bucket name and list of "sensitive" IAM permissions that shall not be
allowed cross-account, create an explicit deny policy for all cross-account
principals, denying access to all IAM permissions in the deny list for all
resources.

Note:
- The deny list is a comma-separated list configured on the Config rule in parameter blacklistedActionPattern
"""
import copy
import json
from typing import Any, Dict

import boto3
from botocore.config import Config

BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})


def connect_to_s3():
    return boto3.client("s3", config=BOTO_CONFIG)


def get_partition():
    return (
        boto3.client("sts", config=BOTO_CONFIG)
        .get_caller_identity()
        .get("Arn")
        .split(":")[1]
    )


class BucketToRemediate:
    def __init__(self, bucket_name):
        self.bucket_name = bucket_name
        self.get_partition_where_running()
        self.initialize_bucket_policy_to_none()

    def __str__(self):
        return json.dumps(self.__dict__)

    def initialize_bucket_policy_to_none(self):
        self.bucket_policy = None

    def get_partition_where_running(self):
        self.partition = get_partition()

    def set_account_id_from_event(self, event):
        self.account_id = event.get("accountid") or exit("AWS Account not specified")

    def set_denylist_from_event(self, event):
        self.denylist = event.get("denylist").split(",") or exit(
            "DenyList is empty or not a comma-delimited string"
        )  # Expect a comma seperated list in a string

    def get_current_bucket_policy(self):
        try:
            self.bucket_policy = (
                connect_to_s3()
                .get_bucket_policy(
                    Bucket=self.bucket_name, ExpectedBucketOwner=self.account_id
                )
                .get("Policy")
            )

        except Exception as e:
            print(e)
            exit(
                f"Failed to retrieve the bucket policy: {self.account_id} {self.bucket_name}"
            )

    def update_bucket_policy(self):
        try:
            connect_to_s3().put_bucket_policy(
                Bucket=self.bucket_name,
                ExpectedBucketOwner=self.account_id,
                Policy=self.bucket_policy,
            )
        except Exception as e:
            print(e)
            exit(
                f"Failed to store the new bucket policy: {self.account_id} {self.bucket_name}"
            )

    def __principal_is_asterisk(self, principals):
        return True if isinstance(principals, str) and principals == "*" else False

    def get_account_principals_from_bucket_policy_statement(self, statement_principals):
        aws_account_principals = []
        for principal_type, principal in statement_principals.items():
            if principal_type != "AWS":
                continue  # not an AWS account
            aws_account_principals = (
                principal if isinstance(principal, list) else [principal]
            )
        return aws_account_principals

    def create_explicit_deny_in_bucket_policy(self):
        new_bucket_policy = json.loads(self.bucket_policy)  # type: ignore[arg-type]
        deny_statement = DenyStatement(self)
        for statement in new_bucket_policy["Statement"]:
            principals = statement.get("Principal", None)
            if principals and not self.__principal_is_asterisk(principals):
                account_principals = (
                    self.get_account_principals_from_bucket_policy_statement(
                        copy.deepcopy(principals)
                    )
                )
                deny_statement.add_next_principal_to_deny(
                    account_principals, self.account_id
                )

        if (
            deny_statement.deny_statement_json
            and len(deny_statement.deny_statement_json["Principal"]["AWS"]) > 0
        ):
            new_bucket_policy["Statement"].append(deny_statement.deny_statement_json)
            self.bucket_policy = json.dumps(new_bucket_policy)
            return True


class DenyStatement:
    def __init__(self, bucket_object):
        self.bucket_object = bucket_object
        self.initialize_deny_statement()

    def initialize_deny_statement(self):
        self.deny_statement_json: Dict[str, Any] = {}
        self.deny_statement_json["Effect"] = "Deny"
        self.deny_statement_json["Principal"] = {"AWS": []}
        self.deny_statement_json["Action"] = self.bucket_object.denylist
        self.deny_statement_json["Resource"] = [
            f"arn:{self.bucket_object.partition}:s3:::{self.bucket_object.bucket_name}",
            f"arn:{self.bucket_object.partition}:s3:::{self.bucket_object.bucket_name}/*",
        ]

    def __str__(self):
        return json.dumps(self.deny_statement_json)

    def add_next_principal_to_deny(self, principals_to_deny, bucket_account):
        if len(principals_to_deny) == 0:
            return
        this_principal = principals_to_deny.pop()
        principal_account = this_principal.split(":")[4]
        if principal_account and principal_account != bucket_account:
            self.add_deny_principal(this_principal)

        self.add_next_principal_to_deny(principals_to_deny, bucket_account)

    def add_deny_principal(self, principal_arn):
        if principal_arn not in self.deny_statement_json["Principal"]["AWS"]:
            self.deny_statement_json["Principal"]["AWS"].append(principal_arn)


def update_bucket_policy(event, _):
    def __get_bucket_from_event(event):
        bucket = event.get("bucket") or exit("Bucket not specified")
        return bucket

    bucket_to_update = BucketToRemediate(__get_bucket_from_event(event))
    bucket_to_update.set_denylist_from_event(event)
    bucket_to_update.set_account_id_from_event(event)
    bucket_to_update.get_current_bucket_policy()
    if bucket_to_update.create_explicit_deny_in_bucket_policy():
        bucket_to_update.update_bucket_policy()
    else:
        exit(
            f"Unable to create an explicit deny statement for {bucket_to_update.bucket_name}"
        )
