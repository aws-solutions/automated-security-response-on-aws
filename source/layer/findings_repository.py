# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from layer.powertools_logger import get_logger

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.client import DynamoDBClient
else:
    DynamoDBClient = object

logger = get_logger("findings_repository")

# Statuses that mean the remediation finished cleanly, so any `error` left on the
# row belongs to an earlier attempt and must not survive the update. Mirrors the
# success values in `layer/metrics.py`; the forward and rollback paths write
# different ones, and both can follow a failed attempt on the same row.
#
# Defined here rather than in `history_repository`, which imports this module: both
# rows of `transact_update_finding_and_history` need the same rule, and one
# definition is what keeps them from drifting apart.
SUCCESS_STATUSES = frozenset({"SUCCESS", "ROLLBACK_SUCCESS"})


class PartialFindingData(TypedDict, total=False):
    """Subset of fields from a Finding table item used for history record creation."""

    accountId: str
    resourceId: str
    resourceType: str
    resourceTypeNormalized: str
    severity: str
    region: str
    lastUpdatedBy: str


class FindingMetricAttributes(TypedDict, total=False):
    """Metric-enrichment attributes stamped on a finding at ingestion and read back to
    enrich the successful-remediation metric. Keys are the snake_case metric field names;
    each is present only when the corresponding attribute exists on the finding item."""

    first_detected_time: str
    finding_notifications_enabled: bool
    finding_remediation_deadline_configured: bool


def get_metric_attributes(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
) -> FindingMetricAttributes:
    """Reads only the metric-enrichment attributes for a finding via a projected GetItem.

    Fetches the first-detected time and the notification/deadline configuration flags used
    to report Mean Time To Remediate, projecting just those attributes so the large
    findingJSON blob is never transferred. Returns an empty dict when the finding or the
    attributes are absent, or on error — enrichment is best-effort and must never block
    metric publishing.
    """
    attributes: FindingMetricAttributes = {}
    try:
        response = dynamodb.get_item(
            TableName=os.getenv("FINDINGS_TABLE_NAME", ""),
            Key={
                "findingType": {"S": finding_type},
                "findingId": {"S": finding_id},
            },
            ProjectionExpression="firstDetectedTime, hasFindingNotificationsEnabled, hasFindingRemediationDeadlineConfigured",
        )
        item = response.get("Item")
        if not item:
            return attributes

        first_detected_time = item.get("firstDetectedTime", {}).get("S")
        if first_detected_time is not None:
            attributes["first_detected_time"] = first_detected_time

        notifications_enabled = item.get("hasFindingNotificationsEnabled", {}).get(
            "BOOL"
        )
        if notifications_enabled is not None:
            attributes["finding_notifications_enabled"] = notifications_enabled

        deadline_configured = item.get(
            "hasFindingRemediationDeadlineConfigured", {}
        ).get("BOOL")
        if deadline_configured is not None:
            attributes["finding_remediation_deadline_configured"] = deadline_configured

        return attributes
    except Exception as e:
        logger.warning(
            "Error retrieving finding metric attributes",
            extra={
                "findingType": finding_type,
                "findingId": finding_id,
                "error": str(e),
            },
        )
        return attributes


def get(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
) -> Optional[dict[str, Any]]:
    try:
        response = dynamodb.get_item(
            TableName=os.getenv("FINDINGS_TABLE_NAME", ""),
            Key={
                "findingType": {"S": finding_type},
                "findingId": {"S": finding_id},
            },
        )

        if "Item" not in response:
            return None

        item: dict[str, Any] = response["Item"]
        return item

    except Exception as e:
        logger.warning(
            "Error retrieving finding data",
            extra={
                "findingType": finding_type,
                "findingId": finding_id,
                "error": str(e),
            },
        )
        return None


def build_update_item(
    finding_type: str,
    finding_id: str,
    remediation_status: str,
    execution_id: str,
    error: Optional[str] = None,
) -> dict[str, Any]:
    update_expression = "SET remediationStatus = :rs"
    remove_expression = ""
    expression_values = {
        ":rs": {"S": remediation_status},
    }
    expression_names = {}

    if execution_id:
        update_expression += ", executionId = :eid"
        expression_values[":eid"] = {"S": execution_id}

    if error:
        update_expression += ", #err = :err"
        expression_names["#err"] = "error"
        expression_values[":err"] = {"S": error}
    elif remediation_status in SUCCESS_STATUSES:
        # The same clear the history row gets, for the same reason: `SET` never removes
        # an attribute, so a failed attempt's `error` would survive a successful retry
        # and leave this row reporting SUCCESS beside a stale message. This is the row
        # the findings list reads, so fixing only the history row left the defect on the
        # copy a customer actually sees.
        #
        # Scoped to the success statuses rather than to "no error was passed", because
        # partial updates legitimately re-assert a failed status without resupplying the
        # message; removing it there would discard why it failed.
        remove_expression = " REMOVE #err"
        expression_names["#err"] = "error"

    # REMOVE is its own clause and has to follow every SET assignment.
    update_expression += remove_expression

    finding_update_item: dict[str, Any] = {
        "Update": {
            "TableName": os.getenv("FINDINGS_TABLE_NAME", ""),
            "Key": {"findingType": {"S": finding_type}, "findingId": {"S": finding_id}},
            "UpdateExpression": update_expression,
            "ExpressionAttributeValues": expression_values,
        }
    }

    if expression_names:
        finding_update_item["Update"]["ExpressionAttributeNames"] = expression_names

    return finding_update_item


def update(
    dynamodb: "DynamoDBClient",
    finding_type: str,
    finding_id: str,
    remediation_status: str,
    execution_id: str,
    error: Optional[str] = None,
) -> None:
    update_item = build_update_item(
        finding_type,
        finding_id,
        remediation_status,
        execution_id,
        error,
    )
    dynamodb.update_item(**update_item["Update"])


def extract_partial_finding_data(item: dict[str, Any]) -> PartialFindingData:
    """Extracts a subset of fields from a Finding DynamoDB item."""
    finding_data: PartialFindingData = {}
    field_mappings = [
        "accountId",
        "resourceId",
        "resourceType",
        "resourceTypeNormalized",
        "severity",
        "region",
        "lastUpdatedBy",
    ]

    for field in field_mappings:
        if field in item:
            finding_data[field] = item[field]["S"]  # type: ignore[literal-required]

    return finding_data
