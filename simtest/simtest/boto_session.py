# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
import botocore

_session = None


def get_session():
    if not _session:
        raise Exception("Session has not been initialized")
    return _session


def create_session(profile, region):
    global _session
    _session = BotoSession(profile, region)
    return _session


class BotoSession:
    def __init__(self, profile, region):
        self._config = botocore.config.Config(
            region_name=region, retries={"max_attempts": 10}
        )
        self._session = boto3.session.Session(profile_name=profile)
        self._partition = None
        self._account = None

    def client(self, name, **kwargs):
        return self._session.client(name, config=self._config, **kwargs)

    def resource(self, name, **kwargs):
        return self._session.resource(name, config=self._config, **kwargs)

    def get_partition(self):
        if not self._partition:
            self._partition = (
                self.client("sts").get_caller_identity()["Arn"].split(":")[1]
            )
        return self._partition

    def get_account(self):
        if not self._account:
            self._account = self.client("sts").get_caller_identity()["Account"]
        return self._account
