# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import urllib.parse
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Tuple
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import ClientError
from layer import awsapi_cached_client

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
else:
    SSMClient = object

# Mapping of error cases from the Orchestrator Step Function
# to more descriptive strings for metric publishing
NORMALIZED_STATUS_REASON_MAPPING = {
    "FAILED": "REMEDIATION_FAILED",
    "LAMBDA_ERROR": "ORCHESTRATOR_FAILED",
    "RUNBOOK_NOT_ACTIVE": "RUNBOOK_NOT_ACTIVE",
    "PLAYBOOK_NOT_ENABLED": "PLAYBOOK_NOT_ENABLED",
    "TIMEDOUT": "REMEDIATION_TIMED_OUT",
    "CANCELLED": "REMEDIATION_CANCELLED",
    "CANCELLING": "REMEDIATION_CANCELLED",
    "ASSUME_ROLE_FAILURE": "ACCOUNT_NOT_ONBOARDED",
    "NO_RUNBOOK": "NO_REMEDIATION_AVAILABLE",
    "NOT_NEW": "FINDING_WORKFLOW_STATE_NOT_NEW",
}


class Metrics(object):
    event_type = ""
    send_metrics_option = "No"
    solution_version: Any = ""
    solution_uuid = None
    session = None
    region = None
    ssm_client: Optional[SSMClient] = None
    metrics_parameter_name = "/Solutions/SO0111/anonymous_metrics_uuid"

    def __init__(self, event_type=""):
        self.session = boto3.session.Session()
        self.region = self.session.region_name

        self.ssm_client = self.connect_to_ssm()

        if not self.send_anonymous_metrics_enabled():
            return

        self.event_type = event_type

        self.__get_solution_uuid()

        try:
            solution_version_parm = "/Solutions/SO0111/version"
            solution_version_from_ssm = (
                self.ssm_client.get_parameter(Name=solution_version_parm)  # type: ignore[union-attr]
                .get("Parameter")
                .get("Value")
            )
        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type == "ParameterNotFound":
                solution_version_from_ssm = "unknown"
            else:
                print(ex)
        except Exception as e:
            print(e)
            raise

        self.solution_version = solution_version_from_ssm

    def send_anonymous_metrics_enabled(self):
        is_enabled = False  # default value
        try:
            ssm_parm = "/Solutions/SO0111/sendAnonymizedMetrics"
            send_anonymous_metrics_from_ssm = (
                self.ssm_client.get_parameter(Name=ssm_parm)  # type: ignore[union-attr]
                .get("Parameter")
                .get("Value")
                .lower()
            )

            if (
                send_anonymous_metrics_from_ssm != "yes"
                and send_anonymous_metrics_from_ssm != "no"
            ):
                print(
                    f'Unexpected value for {ssm_parm}: {send_anonymous_metrics_from_ssm}. Defaulting to "no"'
                )
            elif send_anonymous_metrics_from_ssm == "yes":
                is_enabled = True

        except Exception as e:
            print(e)

        return is_enabled

    def connect_to_ssm(self):
        try:
            if not self.ssm_client:
                new_ssm_client = awsapi_cached_client.AWSCachedClient(
                    self.region
                ).get_connection("ssm")
                return new_ssm_client
        except Exception as e:
            print(f"Could not connect to ssm: {str(e)}")

    def __update_solution_uuid(self, new_uuid):
        self.ssm_client.put_parameter(  # type: ignore[union-attr]
            Name=self.metrics_parameter_name,
            Description="Unique Id for anonymous metrics collection",
            Value=new_uuid,
            Type="String",
        )

    def __get_solution_uuid(self):
        try:
            solution_uuid_from_ssm = (
                self.ssm_client.get_parameter(Name=self.metrics_parameter_name)  # type: ignore[union-attr]
                .get("Parameter")
                .get("Value")
            )
            self.solution_uuid = solution_uuid_from_ssm
        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type == "ParameterNotFound":
                self.solution_uuid = str(uuid.uuid4())
                self.__update_solution_uuid(self.solution_uuid)
            else:
                print(ex)
                raise
        except Exception as e:
            print(e)
            raise

    def get_metrics_from_event(self, event):
        finding = event.get("Finding", None)
        custom_action_name = event.get("CustomActionName", "")

        try:
            if finding is not None:
                metrics_data = {
                    "generator_id": finding.get("GeneratorId"),
                    "type": finding.get("Title"),
                    "productArn": finding.get("ProductArn"),
                    "finding_triggered_by": self.event_type,
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
            if metrics_data is not None and self.send_anonymous_metrics_enabled():
                usage_data = {
                    "Solution": "SO0111",
                    "UUID": self.solution_uuid,
                    "TimeStamp": str(datetime.utcnow().isoformat()),
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
    def get_status_for_anonymized_metrics(status_from_event: str) -> Tuple[str, str]:
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
