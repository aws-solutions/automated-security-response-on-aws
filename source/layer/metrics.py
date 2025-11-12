# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import urllib.parse
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Optional, Tuple
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import ClientError
from layer import awsapi_cached_client
from layer.powertools_logger import get_logger

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
else:
    SSMClient = object

LOG_LEVEL = os.getenv("log_level", "info")
logger = get_logger("metrics", LOG_LEVEL)

# Mapping of error cases from the Orchestrator Step Function
# to more descriptive strings for metric publishing
NORMALIZED_STATUS_REASON_MAPPING = {
    "FAILED": "REMEDIATION_FAILED",
    "LAMBDA_ERROR": "ORCHESTRATOR_FAILED",
    "RUNBOOK_NOT_ACTIVE": "RUNBOOK_NOT_ACTIVE",
    "PLAYBOOK_NOT_ENABLED": "PLAYBOOK_NOT_ENABLED",
    "TIMEDOUT": "REMEDIATION_TIMED_OUT",
    "TIMED_OUT": "REMEDIATION_TIMED_OUT",
    "CANCELLED": "REMEDIATION_CANCELLED",
    "CANCELLING": "REMEDIATION_CANCELLED",
    "ASSUME_ROLE_FAILURE": "ACCOUNT_NOT_ONBOARDED",
    "NO_RUNBOOK": "NO_REMEDIATION_AVAILABLE",
    "NOT_NEW": "FINDING_WORKFLOW_STATE_NOT_NEW",
    "ABORTED": "REMEDIATION_ABORTED",
}
AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "unknown")
STACK_ID = os.getenv("STACK_ID", "unknown")


class Metrics(object):
    old_uuid_parameter_name = (
        "/Solutions/SO0111/anonymous_metrics_uuid"  # deprecated UUID parameter
    )
    ssm_client: Optional[SSMClient] = None
    new_uuid_parameter_name = "/Solutions/SO0111/metrics_uuid"
    solution_version_parm = "/Solutions/SO0111/version"

    def __init__(self):
        self.session = boto3.session.Session()
        self.region: str = self.session.region_name

        self.ssm_client: SSMClient = self.connect_to_ssm()
        self.solution_uuid: str = self.__get_solution_uuid()
        self.solution_version: str = self.__get_solution_version()

    def connect_to_ssm(self):
        try:
            if not self.ssm_client:
                new_ssm_client = awsapi_cached_client.AWSCachedClient(
                    self.region
                ).get_connection("ssm")
                return new_ssm_client
        except Exception as e:
            print(f"Could not connect to ssm: {str(e)}")

    def __try_get_and_destroy_deprecated_uuid_parameter(self) -> Optional[str]:
        """
        The `old_uuid_parameter_name` SSM Parameter is deprecated. This method attempts to fetch the UUID from this parameter
        if it exists, and then deletes the parameter. If the parameter does not exist, it returns None.
        """
        try:
            get_old_parameter_response = self.ssm_client.get_parameter(  # type: ignore[union-attr]
                Name=self.old_uuid_parameter_name,
            )

            existing_uuid = get_old_parameter_response["Parameter"]["Value"]
            self.ssm_client.delete_parameter(  # type: ignore[union-attr]
                Name=self.old_uuid_parameter_name,
            )
            return existing_uuid
        except Exception as e:
            logger.debug(
                f"could not fetch uuid from old SSM parameter {self.old_uuid_parameter_name}",
                error=e,
            )
        return None

    def __update_solution_uuid(self) -> str:
        """
        This function sets the SSM parameter `new_uuid_parameter_name` to a UUID value for metrics publishing, and returns the UUID value used.
        It first attempts to fetch an existing UUID from the SSM parameter where the solution previously stored the UUID (`old_uuid_parameter_name`),
        and uses that existing UUID if available. Otherwise, it uses a newly generated UUID value.
        """
        new_uuid = str(uuid.uuid4())
        existing_uuid = None
        try:
            # try to fetch the old UUID parameter value if it exists, to avoid changing the existing
            # UUID when migrating to the new parameter name
            existing_uuid = self.__try_get_and_destroy_deprecated_uuid_parameter()
        except Exception as e:
            logger.debug(
                f"could not fetch uuid from old SSM parameter {self.old_uuid_parameter_name}, "
                f"setting parameter {self.new_uuid_parameter_name} with a new UUID value instead.",
                error=e,
            )
        try:
            self.ssm_client.put_parameter(  # type: ignore[union-attr]
                Name=self.new_uuid_parameter_name,
                Description="Unique Id for anonymous metrics collection",
                Value=existing_uuid if existing_uuid else new_uuid,
                Type="String",
            )
        except Exception as e:
            logger.debug(
                f"could not set uuid in SSM parameter {self.new_uuid_parameter_name} with value {new_uuid}",
                error=e,
            )
            return "unknown"
        return existing_uuid if existing_uuid else new_uuid

    def __get_solution_version(self) -> str:
        try:
            return (
                self.ssm_client.get_parameter(Name=self.solution_version_parm)  # type: ignore[union-attr]
                .get("Parameter", {})
                .get("Value", "unknown")
            )
        except Exception as e:
            logger.debug(
                f"Encountered error fetching solution version from ssm parameter {self.solution_version_parm}",
                error=e,
            )
            return "unknown"

    def __get_solution_uuid(self) -> str:
        try:
            return self.ssm_client.get_parameter(Name=self.new_uuid_parameter_name)[  # type: ignore[union-attr]
                "Parameter"
            ][
                "Value"
            ]
        except ClientError as ex:
            if ex.response["Error"]["Code"] == "ParameterNotFound":
                return self.__update_solution_uuid()
            return "unknown"
        except Exception as e:
            logger.debug(
                f"could not fetch uuid from SSM parameter {self.new_uuid_parameter_name}",
                error=e,
            )
            return "unknown"

    def get_metrics_from_event(self, event):
        finding = event.get("Finding", None)
        event_type = event.get("EventType", "unknown")
        custom_action_name = event.get("CustomActionName", "")

        try:
            if finding is not None:
                metrics_data = {
                    "generator_id": finding.get("GeneratorId"),
                    "type": finding.get("Title"),
                    "productArn": finding.get("ProductArn"),
                    "finding_triggered_by": event_type,
                    "region": self.region,
                    "custom_action_name": custom_action_name,
                }
            else:
                metrics_data = {}
            return metrics_data
        except Exception as excep:
            print(excep)
            return {}

    def send_metrics(self, metrics_data):
        try:
            if metrics_data is not None:
                usage_data = {
                    "Solution": "SO0111",
                    "UUID": self.solution_uuid,
                    "AccountId": AWS_ACCOUNT_ID,
                    "StackId": STACK_ID,
                    "TimeStamp": str(datetime.now(UTC).isoformat()),
                    "Data": metrics_data,
                    "Version": self.solution_version,
                }
                print(f"Sending metrics data {json.dumps(usage_data)}")
                self.post_metrics_to_api(usage_data)

            else:
                return
        except Exception as excep:
            print(excep)

    def post_metrics_to_api(self, request_data):
        url = "https://metrics.awssolutionsbuilder.com/generic"
        url_encoded_request_data = urllib.parse.quote(json.dumps(request_data))
        print(f"url_encoded_request_data: {url_encoded_request_data}")
        req = Request(
            url,
            method="POST",
            data=bytes(url_encoded_request_data, encoding="utf8"),
            headers={"Content-Type": "application/json"},
        )
        urlopen(req)  # nosec

    @staticmethod
    def get_status_for_metrics(status_from_event: str) -> Tuple[str, str]:
        """
        Takes the status received from the event which invoked SendNotifications
        and returns an object containing the normalized status & reason for the status.
        A reason will only be provided if the status is "FAILED".
        """
        status_from_event_upper = status_from_event.upper()
        if status_from_event_upper == "SUCCESS":
            status = "SUCCESS"
        elif status_from_event_upper == "QUEUED":
            status = "PENDING"
        else:
            status = "FAILED"

        reason = ""
        if status == "FAILED":
            reason = NORMALIZED_STATUS_REASON_MAPPING.get(
                status_from_event_upper, "UNKNOWN"
            )

        return status, reason
