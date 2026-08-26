# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, Literal, Optional, cast
from urllib.parse import quote_plus

from botocore.exceptions import ClientError
from layer.awsapi_cached_client import AWSCachedClient
from layer.findings_repository import PartialFindingData, extract_partial_finding_data
from layer.findings_repository import get as get_finding
from layer.findings_repository import update as update_finding

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.client import DynamoDBClient

from layer.history_repository import (
    RemediationUpdateRequest,
    transact_create_history_and_update_finding,
    transact_update_finding_and_history,
)
from layer.metrics import NORMALIZED_STATUS_REASON_MAPPING
from layer.powertools_logger import get_logger

logger = get_logger("remediation_data_service")

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")


def get_console_host(partition: str) -> str:
    console_hosts = {
        "aws": "console.aws.amazon.com",
        "aws-us-gov": "console.amazonaws-us-gov.com",
        "aws-cn": "console.amazonaws.cn",
    }
    return console_hosts.get(partition, console_hosts["aws"])


def get_security_hub_console_url(
    finding_id: str, region: Optional[str] = None, partition: Optional[str] = None
) -> str:
    """Generates Security Hub finding console URL."""
    securityhub_v2_enabled = (
        os.getenv("SECURITY_HUB_V2_ENABLED", "false").lower() == "true"
    )
    aws_region = region or os.getenv("AWS_REGION", "us-east-1")
    aws_partition = partition or cast(str, os.getenv("AWS_PARTITION", "aws"))

    host = get_console_host(aws_partition)

    if securityhub_v2_enabled:
        default_url = f"/securityhub/v2/home?region={aws_region}#/findings?search=finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253A{quote_plus(finding_id)}"
    else:
        default_url = f"/securityhub/home?region={aws_region}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{quote_plus(finding_id)}"

    url_pattern = os.getenv("CONSOLE_URL_PATTERN", default_url)

    return f"https://{host}{url_pattern}"


# Canonical remediation status values map_remediation_status can return. Fixed
# set, so a Literal documents the valid outputs and lets the type checker verify
# the mapping for callers.
MappedRemediationStatus = Literal[
    "SUCCESS",
    "NOT_STARTED",
    "IN_PROGRESS",
    "FAILED",
    "ROLLBACK_IN_PROGRESS",
    "ROLLBACK_SUCCESS",
    "ROLLBACK_FAILED",
]


def map_remediation_status(status: Optional[str]) -> MappedRemediationStatus:
    if not status:
        return "NOT_STARTED"

    status_upper = status.upper()

    if status_upper == "SUCCESS":
        return "SUCCESS"
    if status_upper == "NOT_STARTED":
        return "NOT_STARTED"
    if status_upper == "ROLLBACK_IN_PROGRESS":
        return "ROLLBACK_IN_PROGRESS"
    if status_upper == "ROLLBACK_SUCCESS":
        return "ROLLBACK_SUCCESS"
    if status_upper == "ROLLBACK_FAILED":
        return "ROLLBACK_FAILED"

    if status_upper in ("QUEUED", "RUNNING", "IN_PROGRESS"):
        return "IN_PROGRESS"

    if status_upper in list(NORMALIZED_STATUS_REASON_MAPPING.keys()):
        logger.debug(
            f"Mapping original failed remediation status {status_upper} to 'FAILED'"
        )
        return "FAILED"

    logger.warning(f"Unknown remediation status '{status}', mapping to FAILED")
    return "FAILED"


def get_finding_data(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
) -> Optional[PartialFindingData]:
    item = get_finding(dynamodb, finding_type, finding_id)
    if not item:
        return None
    return extract_partial_finding_data(item)


def update_remediation_status_and_history(request: RemediationUpdateRequest) -> None:

    if not request.validate():
        return

    try:
        aws_client = AWSCachedClient(AWS_REGION)
        dynamodb = aws_client.get_connection("dynamodb")

        logger.debug(
            "Processing remediation status update",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
                "error": request.error,
            },
        )

        success = try_update_with_existing_history(dynamodb, request)

        if not success:
            logger.info(
                "History item not found, creating new history record via fallback",
                extra={
                    "findingId": request.finding_id,
                    "executionId": request.execution_id,
                    "findingType": request.finding_type,
                    "remediationStatus": request.remediation_status,
                },
            )
            create_history_with_finding_update(dynamodb, request)

    except ClientError as e:
        logger.error(
            "Failed to update remediation status",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "error": str(e),
            },
        )
        raise
    except Exception as e:
        logger.error(
            "Unexpected error updating remediation status",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "error": str(e),
            },
        )
        raise


def try_update_with_existing_history(
    dynamodb: "DynamoDBClient",
    request: RemediationUpdateRequest,
) -> bool:
    try:
        logger.debug(
            "Attempting to update existing history item",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
            },
        )

        transact_update_finding_and_history(
            dynamodb,
            request.finding_type,
            request.finding_id,
            request.execution_id,
            request.remediation_status,
            error=request.error,
            finding_json=request.finding_json,
            backup_s3_key=request.backup_s3_key,
        )

        logger.debug(
            "Successfully updated existing history item via transaction",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
            },
        )
        return True

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        logger.warning(
            "Transaction failed while trying to update existing history",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "remediationStatus": request.remediation_status,
                "errorCode": error_code,
                "errorMessage": str(e),
            },
        )

        if error_code == "TransactionCanceledException":
            cancellation_reasons = e.response.get("CancellationReasons", [])
            for i, reason in enumerate(cancellation_reasons):
                if reason.get("Code") == "ConditionalCheckFailed":
                    logger.warning(
                        "History item not found due to conditional check failure, will attempt fallback creation",
                        extra={
                            "findingId": request.finding_id,
                            "executionId": request.execution_id,
                            "findingType": request.finding_type,
                            "remediationStatus": request.remediation_status,
                            "cancellationReason": reason,
                            "transactionItemIndex": i,
                        },
                    )
                    return False

        raise


def create_history_with_finding_update(
    dynamodb: "DynamoDBClient",
    request: RemediationUpdateRequest,
) -> None:
    finding_data = None

    try:
        finding_data = get_finding_data(
            dynamodb, request.finding_type, request.finding_id
        )
    except Exception as e:
        logger.warning(
            "Could not retrieve finding data for history creation, proceeding with minimal data",
            extra={
                "findingId": request.finding_id,
                "error": str(e),
            },
        )

    try:
        extra_fields: Optional[dict[str, str]] = (
            {
                k: str(v)
                for k, v in finding_data.items()
                if k
                not in [
                    "accountId",
                    "resourceId",
                    "resourceType",
                    "severity",
                    "region",
                    "lastUpdatedBy",
                ]
            }
            if finding_data
            else None
        )

        transact_create_history_and_update_finding(
            dynamodb,
            request,
            extra_fields,
            bool(finding_data),
        )

        logger.info(
            "Successfully created remediation history via fallback",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
            },
        )

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")

        if error_code == "TransactionCanceledException":
            update_finding_only(dynamodb, request)
        else:
            raise


def update_finding_only(
    dynamodb: "DynamoDBClient",
    request: RemediationUpdateRequest,
) -> None:
    try:
        update_finding(
            dynamodb,
            request.finding_type,
            request.finding_id,
            request.remediation_status,
            request.execution_id,
            request.error,
        )

        logger.debug(
            "Successfully updated finding only after history operation failure",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
            },
        )
    except Exception as e:
        logger.error(
            "Failed to update finding after history operation failure",
            extra={
                "findingId": request.finding_id,
                "executionId": request.execution_id,
                "findingType": request.finding_type,
                "error": str(e),
            },
        )
        raise
