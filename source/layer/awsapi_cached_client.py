# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, Any, Final, Optional

import boto3
from boto3 import Session
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_sts.client import STSClient
else:
    STSClient = object


class AWSCachedClient:
    """
    Maintains a hash of AWS API Client connections by region and service
    """

    account: Optional[str] = ""
    region: Optional[str] = ""
    client: dict[str, Any] = {}
    solution_id = ""
    solution_version = "undefined"

    def __init__(self, region: Optional[str]) -> None:
        """
        Create a Boto3 Client object. Region is used for operations such
        as retrieving account number, and as the default for get_connection.
        """
        self.solution_id = os.getenv("SOLUTION_ID", "SO0111")
        self.solution_version = os.getenv("SOLUTION_VERSION", "undefined")
        self.region = region
        self.boto_config = Config(
            user_agent_extra=f"AwsSolution/{self.solution_id}/{self.solution_version}",
            retries={"max_attempts": 10, "mode": "standard"},
        )

        self.account = self._get_local_account_id()

    def get_connection(self, service: str, region: Optional[str] = None) -> Any:
        """Connect to AWS api"""

        if not region:
            region = self.region

        if service not in self.client:
            self.client[service] = {}

        if region not in self.client[service]:
            self.client[service][region] = boto3.client(
                service, region_name=region, config=self.boto_config
            )

        return self.client[service][region]

    def _get_local_account_id(self) -> Optional[str]:
        """
        get local account info
        """
        sts: STSClient = self.get_connection("sts", self.region)
        aws_account_id = sts.get_caller_identity().get("Account")
        return aws_account_id


class MissingAssumedRole(Exception):
    pass


class BotoSession:
    client_props: dict[str, Any] = {}
    resource_props: dict[str, Any] = {}
    STS: Optional[STSClient] = None
    partition: Optional[str] = None
    session: Optional[boto3.session.Session] = None
    target: Optional[str] = None
    role: Optional[str] = None

    def create_session(self) -> None:
        self.STS = None
        self.STS = self._create_sts_client()

        if not self.target:
            self.target = self.STS.get_caller_identity()["Account"]
        remote_account = self.STS.assume_role(
            RoleArn="arn:"  # type: ignore[operator]
            + self.partition
            + ":iam::"
            + self.target
            + ":role/"
            + self.role,
            RoleSessionName="sechub_admin",
        )
        self.session = boto3.session.Session(
            aws_access_key_id=remote_account["Credentials"]["AccessKeyId"],
            aws_secret_access_key=remote_account["Credentials"]["SecretAccessKey"],
            aws_session_token=remote_account["Credentials"]["SessionToken"],
        )

        boto3.setup_default_session()

    def _create_sts_client(self) -> Any:
        """
        Create the sts client
        """

        session: Final = Session()
        china_domain_suffix = (
            ".cn" if session.region_name in ["cn-north-1", "cn-northwest-1"] else ""
        )
        sts_regional_endpoint: Final = str.format(
            "https://sts.{}.amazonaws.com{}", session.region_name, china_domain_suffix
        )
        # STS client __must__ use a regional endpoint so that tokens are version 2.
        # version 1 tokens are not valid in opt-in regions unless enabled on an
        # account level
        return session.client(
            "sts",
            region_name=session.region_name,
            endpoint_url=sts_regional_endpoint,
            config=self.boto_config,
        )

    def __init__(
        self,
        account: Optional[str] = None,
        role: Optional[str] = None,
        partition: Optional[str] = None,
    ) -> None:
        """
        Create a session
        account: None or the target account
        """
        # Default partition to 'aws'
        if not partition:
            partition = "aws"
        self.target = account
        if not role:
            raise MissingAssumedRole
        else:
            self.role = role
        self.session = None
        self.partition = os.getenv("AWS_PARTITION", partition)
        self.solution_id = os.getenv("SOLUTION_ID", "SO0111")
        self.solution_version = os.getenv("SOLUTION_VERSION", "undefined")
        self.boto_config = Config(
            user_agent_extra=f"AwsSolution/{self.solution_id}/{self.solution_version}",
            retries={"max_attempts": 10, "mode": "standard"},
        )
        self.create_session()

    def client(self, name: str, **kwargs: Any) -> Any:
        self.client_props[name] = self.session.client(  # type: ignore[union-attr]
            name, config=self.boto_config, **kwargs
        )
        return self.client_props[name]

    def resource(self, name: str, **kwargs: Any) -> Any:
        self.resource_props[name] = self.session.resource(  # type: ignore[union-attr]
            name, config=self.boto_config, **kwargs
        )
        return self.resource_props[name]
