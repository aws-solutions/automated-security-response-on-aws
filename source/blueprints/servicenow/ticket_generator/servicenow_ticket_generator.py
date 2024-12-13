# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, TypedDict, cast
from urllib.parse import urlparse

import boto3
from aws_lambda_powertools import Logger, Tracer
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard"})

SOLUTION_ID = os.getenv("solution_id", "SO0111")

SERVICENOW_HOST_REGEX = r"^.+\.service-now\.com$"  # Used to validate the provided instance URI, modify as necessary
SERVICENOW_TABLE_POST = "/api/now/table/"  # POST resource for creating an Issue in ServiceNow: https://docs.servicenow.com/bundle/xanadu-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html#title_table-POST

logger = Logger()
logger.append_keys(solutionId=SOLUTION_ID)
tracer = Tracer()

SERVICENOW_SEVERITY_MAPPING = {
    "INFORMATIONAL": "3",
    "LOW": "3",
    "MEDIUM": "2",
    "HIGH": "1",
    "CRITICAL": "1",
}


class RemediationInfo(TypedDict):
    """
    Remediation specific details that are passed in the event payload.
    These are used to populate the ServiceNow ticket fields.
    """

    Message: str
    FindingDescription: str
    FindingSeverity: str
    SecurityControlId: str
    FindingAccountId: str
    AffectedResource: str


class Event(TypedDict):
    """
    Event payload passed to the lambda_handler by the Orchestrator step function.
    """

    RemediationInfo: RemediationInfo


class ProjectInfo(TypedDict):
    """
    Contains the ServiceNow instance URI & table name where tickets will be created.
    """

    InstanceURI: str
    TableName: str


class CreateTicketResponse(TypedDict):
    """
    Response from the create_ticket method.
    Contains details from the ServiceNow API response.
    """

    TicketURL: str
    Ok: bool
    ResponseCode: str
    ResponseReason: str


def connect_to_service(service: str) -> Any:
    return boto3.client(service, config=boto_config)


@logger.inject_lambda_context
@tracer.capture_lambda_handler
def lambda_handler(event: Event, _: Any) -> CreateTicketResponse:
    instance_uri = cast(str, os.getenv("INSTANCE_URI"))
    table_name = cast(str, os.getenv("TABLE_NAME"))
    secret_arn = cast(str, os.getenv("SECRET_ARN"))

    remediation_info = event["RemediationInfo"]
    try:
        project_info: ProjectInfo = {
            "InstanceURI": instance_uri,
            "TableName": table_name,
        }
        post_endpoint = get_post_endpoint_from_project_info(project_info)

        api_key = get_api_credentials(secret_arn)

        account_alias = get_account_alias(remediation_info["FindingAccountId"])

        create_ticket_response: CreateTicketResponse = create_ticket(
            remediation_info,
            project_info,
            post_endpoint,
            api_key,
            account_alias,
        )

        logger.info(f"Create Ticket Response: {create_ticket_response}")
        return create_ticket_response
    except Exception as e:
        logger.exception(e)
        return {
            "Ok": False,
            "ResponseCode": "Error",
            "ResponseReason": str(e),
            "TicketURL": "",
        }


def get_post_endpoint_from_project_info(project_info: ProjectInfo) -> str:
    """
    Validates the provided instance URI against the expected structure.
    Returns the REST endpoint used to create the ticket.
    """
    instance_uri = project_info["InstanceURI"]
    table_name = project_info["TableName"]
    if not re.match(SERVICENOW_HOST_REGEX, urlparse(instance_uri).netloc):
        raise RuntimeError(
            f"ServiceNow Instance URI {instance_uri} does not match expected structure {SERVICENOW_HOST_REGEX}"
        )

    return f"{instance_uri}{SERVICENOW_TABLE_POST}{table_name}"


def get_api_credentials(secret_arn: str) -> str:
    """
    Retrieves the ServiceNow API credentials from the Secrets Manager ARN.
    """

    secrets_manager_client = connect_to_service("secretsmanager")
    try:
        response = secrets_manager_client.get_secret_value(SecretId=secret_arn)

        if "SecretString" not in response:
            raise RuntimeError(
                f"Missing SecretString in response for {secret_arn}, please ensure the secret was not stored as binary data."
            )
        secret_string = response["SecretString"]
        json_secret = json.loads(secret_string)

        if "API_Key" not in json_secret:
            raise RuntimeError(f"Missing required key in secret {secret_arn}: API_Key")

        return cast(str, json_secret["API_Key"])

    except ClientError as e:
        logger.exception(f"Error retrieving secret {secret_arn}: {e}")
        raise RuntimeError(f"Could not retrieve value stored in secret {secret_arn}")
    except Exception as e:
        error_msg = f"Unexpected error while creating retrieving api credentials: {e}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg)


def get_account_alias(account_id: str) -> str:
    default_account_alias = account_id
    try:
        organizations_client = connect_to_service("organizations")
        accounts = []

        paginator = organizations_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            accounts.extend(page["Accounts"])
        return next(
            (account["Name"] for account in accounts if account["Id"] == account_id),
            default_account_alias,
        )
    except Exception as e:
        logger.error(f"encountered error retrieving account alias: {str(e)}")
        return default_account_alias


def create_ticket(
    remediation_info: RemediationInfo,
    project_info: ProjectInfo,
    endpoint: str,
    api_credentials: str,
    account_alias: str,
) -> CreateTicketResponse:
    """
    Creates a ServieNow ticket using the provided `remediation_info`.
    Update the `data` dictionary as needed to control how tickets are created.
    """

    # Headers for the request
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-sn-apikey": api_credentials,
    }

    # Map the Security Hub finding severity to ServiceNow-friendly priority
    servicenow_severity = SERVICENOW_SEVERITY_MAPPING.get(
        remediation_info["FindingSeverity"].upper(), ""
    )
    data = {  # You may customize this payload to add/remove fields based on your ServiceNow table configuration.
        "description": f"ASR Remediation Result: {remediation_info['Message']} \n\nFinding Description: {remediation_info['FindingDescription']} \n\nAffected Resource: {remediation_info['AffectedResource']} \n\n Account Alias: {account_alias}",
        "short_description": f"ASR: Remediation completed for {remediation_info['SecurityControlId']} in account {remediation_info['FindingAccountId']}",
        "category": "Software",
        "severity": servicenow_severity,
        "impact": servicenow_severity,
        "urgency": servicenow_severity,
    }

    try:
        # Convert the data to a JSON-encoded byte stream
        json_data = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(
            endpoint, data=json_data, headers=headers, method="POST"
        )

        # Send the request and receive the response
        with urllib.request.urlopen(req) as response:
            status_code = response.getcode()
            response_body = response.read().decode("utf-8")
            response_json = json.loads(response_body)

            logger.info(
                f"Received response from ServiceNow resource {endpoint} with Status Code: {status_code}"
            )
            logger.debug(f"ServiceNow Response Body: {response_body}")

            sys_id = response_json.get("result", {}).get("sys_id", "unknown")
            instance_uri = project_info["InstanceURI"]
            table_name = project_info["TableName"]
            return {
                "TicketURL": f"{instance_uri}/nav_to.do?uri={table_name}.do?sys_id={sys_id}",
                "Ok": True,
                "ResponseCode": str(status_code),
                "ResponseReason": response_body,
            }
    except urllib.error.HTTPError as e:
        logger.error(f"Encountered an error during ServiceNow request: {str(e)}")
        return {
            "Ok": False,
            "ResponseCode": str(e.code),
            "ResponseReason": e.reason,
            "TicketURL": "",
        }
    except Exception as e:
        error_msg = f"Unexpected error while creating ticket: {e}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg)
