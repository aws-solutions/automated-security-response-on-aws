# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, TypedDict, cast
from urllib.parse import urlparse

import boto3
from aws_lambda_powertools import Logger, Tracer
from botocore.config import Config
from botocore.exceptions import ClientError
from layer.secrets_cache import get_secret_value_cached

boto_config = Config(retries={"mode": "standard"})

SOLUTION_ID = os.getenv("solution_id", "SO0111")

JIRA_HOST_REGEX = r"^.+\.atlassian\.net$"  # Used to validate the provided instance URI, modify as necessary
JIRA_V2_ISSUE_POST = "/rest/api/2/issue"  # POST resource for creating an Issue in Jira: https://developer.atlassian.com/server/jira/platform/rest/v10000/api-group-issue/#api-api-2-issue-post

# HTTP timeout configuration
HTTP_TIMEOUT = 12  # seconds

logger = Logger()
logger.append_keys(solutionId=SOLUTION_ID)
tracer = Tracer()

JIRA_SEVERITY_MAPPING = {
    "INFORMATIONAL": "5",
    "LOW": "4",
    "MEDIUM": "3",
    "HIGH": "2",
    "CRITICAL": "1",
}

# Cache for Jira account ID to avoid repeated API calls in warm Lambda
_cached_jira_account_id: str = ""


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


def get_jira_headers(api_credentials: APICredentials) -> Dict[str, str]:
    """Build Jira API request headers with authentication."""
    auth_credentials = f"{api_credentials['Username']}:{api_credentials['Password']}"
    encoded_credentials = base64.b64encode(auth_credentials.encode("utf-8")).decode(
        "utf-8"
    )
    content_type = "application/json"
    return {
        "Accept": content_type,
        "Content-Type": content_type,
        "Authorization": f"Basic {encoded_credentials}",
    }


def create_response(
    ok: bool, code: str, reason: str, ticket_url: str = ""
) -> CreateTicketResponse:
    """Create a standardized ticket response."""
    return {
        "Ok": ok,
        "ResponseCode": code,
        "ResponseReason": reason,
        "TicketURL": ticket_url,
    }


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
        return create_response(False, "Error", str(e))


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
    try:
        secret_string = get_secret_value_cached(secret_arn)
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


def get_current_user_account_id(
    instance_uri: str, api_credentials: APICredentials
) -> str:
    """Retrieves the current user's account ID from Jira API."""
    global _cached_jira_account_id

    if _cached_jira_account_id:
        return _cached_jira_account_id

    headers = get_jira_headers(api_credentials)
    myself_endpoint = f"{instance_uri}/rest/api/2/myself"

    try:
        req = urllib.request.Request(myself_endpoint, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
            response_body = response.read().decode("utf-8")
            user_data = json.loads(response_body)
            _cached_jira_account_id = str(user_data.get("accountId", ""))
            return _cached_jira_account_id
    except Exception as e:
        logger.error(f"Error retrieving current user account ID: {e}")
        return ""


def get_account_alias(account_id: str) -> str:
    if not account_id:
        return "Unknown"

    default_account_alias = account_id

    if os.getenv("DISABLE_ACCOUNT_ALIAS_LOOKUP", "false").lower() == "true":
        logger.debug("Account alias lookup disabled via environment variable")
        return default_account_alias

    try:
        organizations_client = connect_to_service("organizations")
        response = organizations_client.describe_account(AccountId=account_id)
        return str(response["Account"]["Name"])
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
    headers = get_jira_headers(api_credentials)

    # Get field mappings from environment variable
    fields_mapping_str = os.getenv("JIRA_FIELDS_MAPPING", "")
    if fields_mapping_str:
        try:
            fields_override = json.loads(fields_mapping_str)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JIRA_FIELDS_MAPPING JSON: {e}")
            return create_response(
                False, "ConfigError", f"Invalid JIRA_FIELDS_MAPPING configuration: {e}"
            )
    else:
        fields_override = {}

    # Populate reporter field if not provided
    if "reporter" not in fields_override or not fields_override.get("reporter", {}).get(
        "accountId"
    ):
        account_id = get_current_user_account_id(instance_uri, api_credentials)
        if account_id:
            fields_override["reporter"] = {"accountId": account_id}
        else:
            logger.error(
                "Failed to retrieve current user account ID for reporter field"
            )
            return create_response(
                False,
                "ConfigError",
                "Failed to retrieve reporter account ID from Jira API",
            )

    # Map the Security Hub finding severity to Jira-friendly priority
    jira_severity = JIRA_SEVERITY_MAPPING.get(
        remediation_info["FindingSeverity"].upper(), "3"
    )

    data = {
        "fields": {
            "description": f"ASR Remediation Result: {remediation_info['Message']} \n\nFinding Description: {remediation_info['FindingDescription']} \n\nAffected Resource: {remediation_info['AffectedResource']} \n\n Account Alias: {account_alias}",
            "summary": f"ASR: Remediation completed for {remediation_info['SecurityControlId']} in account {remediation_info['FindingAccountId']}",
            "issuetype": {
                "id": "10006"
            },  # Varies by Jira project (e.g., 10006 for Task)
            "project": {"key": project_name},
            "labels": ["ASR"],
            "priority": {
                "id": jira_severity
            },  # 1 (Highest), 2 (High), 3 (Medium), 4 (Low), 5 (Lowest)
        }
    }

    # Override with custom fields from JIRA_FIELDS_MAPPING
    data["fields"].update(fields_override)

    try:
        # Convert the data to a JSON-encoded byte stream
        json_data = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(
            endpoint, data=json_data, headers=headers, method="POST"
        )

        # Send the request and receive the response
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
            status_code = response.getcode()
            response_body = response.read().decode("utf-8")
            response_json = json.loads(response_body)

            logger.info(
                f"Received response from Jira resource {endpoint} with Status Code: {status_code}"
            )
            logger.debug(f"Jira Response Body: {response_body}")

            ticket_key = response_json.get("key", "unknown")
            return create_response(
                True,
                str(status_code),
                response_body,
                f"{instance_uri}/browse/{ticket_key}",
            )
    except urllib.error.HTTPError as e:
        logger.error(f"Encountered an error during Jira HTTP request: {str(e)}")
        return create_response(False, str(e.code), e.reason)
    except Exception as e:
        error_msg = f"Unexpected error while creating ticket: {e}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg)
