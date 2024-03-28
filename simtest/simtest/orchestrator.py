# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

from simtest.boto_session import get_session

_orchestrator = None


def get_orchestrator():
    if not _orchestrator:
        raise Exception("Orchestrator has not been initialized")
    return _orchestrator


def create_orchestrator(region):
    global _orchestrator
    _orchestrator = Orchestrator(region)
    return _orchestrator


class Orchestrator:
    def __init__(self, region):
        self._session = get_session()
        self._region = region
        self._arn = f"arn:{self._session.get_partition()}:states:{self._region}:{self._session.get_account()}:stateMachine:SO0111-SHARR-Orchestrator"

    def invoke(self, payload):
        try:
            sfn = self._session.client("stepfunctions", region_name=self._region)
            print(f"Invoking Orchestrator in {self._region}")
            sfn.start_execution(stateMachineArn=self._arn, input=json.dumps(payload))
        except Exception as e:
            print(e)
            print(
                f"start_execution for Orchestrator step function failed in {self._region}"
            )

    def get_region(self):
        return self._region
