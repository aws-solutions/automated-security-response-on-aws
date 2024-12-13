# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
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

JIRA_HOST_REGEX = r"^.+\.atlassian\.net$"  # Used to validate the provided instance URI, modify as necessary
JIRA_V2_ISSUE_POST = "/rest/api/2/issue"  # POST resource for creating an Issue in Jira: https://developer.atlassian.com/server/jira/platform/rest/v10000/api-group-issue/#api-api-2-issue-post

logger = Logger()
logger.append_keys(solutionId=SOLUTION_ID)
tracer = Tracer()

JIRA_SEVERITY_MAPPING = {
    "INFORMATIONAL": "Lowest",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Highest",
}


class RemediationInfo(TypedDict):
    """
    Remediation specific details that are passed in the event payload.
    These are used to populate the Jira ticket fields.
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


class APICredentials(TypedDict):
    """
    Credentials for the Jira API.
    These are retrieved from the Secrets Manager resource.
    """

    Username: str
    Password: str


class CreateTicketResponse(TypedDict):
    """
    Response from the create_ticket method.
    Contains details from the Jira API response.
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
    project_name = cast(str, os.getenv("PROJECT_NAME"))
    secret_arn = cast(str, os.getenv("SECRET_ARN"))

    remediation_info = event["RemediationInfo"]
    try:
        post_endpoint = get_post_endpoint_from_instance_uri(instance_uri)

        api_credentials: APICredentials = get_api_credentials(secret_arn)

        account_alias = get_account_alias(remediation_info["FindingAccountId"])

        create_ticket_response: CreateTicketResponse = create_ticket(
            remediation_info,
            instance_uri,
            post_endpoint,
            api_credentials,
            project_name,
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


def get_post_endpoint_from_instance_uri(instance_uri: str) -> str:
    """
    Validates the provided instance URI against the expected structure.
    Returns the REST endpoint used to create the ticket.
    """

    if not re.match(JIRA_HOST_REGEX, urlparse(instance_uri).netloc):
        raise RuntimeError(
            f"Jira Instance URI {instance_uri} does not match expected structure {JIRA_HOST_REGEX}"
        )

    return f"{instance_uri}{JIRA_V2_ISSUE_POST}"


def get_api_credentials(secret_arn: str) -> APICredentials:
    """
    Retrieves the Jira API credentials from the Secrets Manager ARN.
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

        if "Username" not in json_secret or "Password" not in json_secret:
            raise RuntimeError(
                f"Missing required keys in secret {secret_arn}: Username, Password"
            )

        return {
            "Username": json_secret["Username"],
            "Password": json_secret["Password"],
        }

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
    instance_uri: str,
    endpoint: str,
    api_credentials: APICredentials,
    project_name: str,
    account_alias: str,
) -> CreateTicketResponse:
    """
    Creates a Jira ticket using the provided `remediation_info`.
    Update the `data` dictionary as needed to control how tickets are created.
    """

    # Prepare the credentials using HTTP Basic Authentication
    auth_credentials = f"{api_credentials['Username']}:{api_credentials['Password']}"
    encoded_credentials = base64.b64encode(auth_credentials.encode("utf-8")).decode(
        "utf-8"
    )

    # Headers for the request
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Basic {encoded_credentials}",
    }

    # Map the Security Hub finding severity to Jira-friendly priority
    jira_severity = JIRA_SEVERITY_MAPPING.get(
        remediation_info["FindingSeverity"].upper(), ""
    )
    data = {
        "fields": {  # You may customize this payload to add/remove fields based on your Jira project configuration.
            "description": f"ASR Remediation Result: {remediation_info['Message']} \n\nFinding Description: {remediation_info['FindingDescription']} \n\nAffected Resource: {remediation_info['AffectedResource']} \n\n Account Alias: {account_alias}",
            "summary": f"ASR: Remediation completed for {remediation_info['SecurityControlId']} in account {remediation_info['FindingAccountId']}",
            "issuetype": {"name": "Bug"},
            "reporter": {"name": "ASR"},
            "priority": {"name": jira_severity},
            "project": {"key": project_name},
        }
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
                f"Received response from Jira resource {endpoint} with Status Code: {status_code}"
            )
            logger.debug(f"Jira Response Body: {response_body}")

            ticket_key = response_json.get("key", "unknown")
            return {
                "TicketURL": f"{instance_uri}/browse/{ticket_key}",
                "Ok": True,
                "ResponseCode": str(status_code),
                "ResponseReason": response_body,
            }
    except urllib.error.HTTPError as e:
        logger.error(f"Encountered an error during Jira HTTP request: {str(e)}")
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
