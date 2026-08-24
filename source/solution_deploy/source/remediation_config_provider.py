# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider for populating remediation configuration DynamoDB table"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from os import getenv
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict, cast

import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import Table
import cfnresponse
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
    event_source,
)
from aws_lambda_powertools.utilities.typing import LambdaContext
from layer.powertools_logger import get_logger
from layer.tracer_utils import init_tracer

FilterMode = Literal["include", "exclude"]


class SecurityControlItem(TypedDict):
    """Mirrors the SecurityControl schema in source/data-models/securityControl.ts.

    Note: 'filters' is omitted when empty because DynamoDB does not allow empty sets.
    The application layer treats a missing 'filters' attribute as an empty set.
    """

    controlId: str
    description: str
    automatedRemediationEnabled: bool
    filters: NotRequired[set[str]]
    filterMode: FilterMode
    version: int
    lastModified: str
    modifiedBy: str


# initialize logger
LOG_LEVEL = getenv("POWERTOOLS_LOG_LEVEL", "info")
logger = get_logger("remediation_config_provider", LOG_LEVEL)
tracer = init_tracer()

# Explicit timeouts bound each network call so a hung endpoint cannot stall the
# custom-resource Lambda for its full timeout; standard retries add headroom.
BOTO_CONFIG = Config(retries={"mode": "standard"}, connect_timeout=5, read_timeout=10)

# Region where solutions-reference
PARTITION_TO_BUCKET_REGION = {
    "aws": "us-east-1",
    "aws-cn": "cn-north-1",
    "aws-us-gov": "us-gov-west-1",
}

PARTITION_TO_BUCKET_SUFFIX = {
    "aws": "",
    "aws-cn": "-cn",
    "aws-us-gov": "-us-gov",
}


def get_supported_controls() -> list[str]:
    """Fetch supported controls from S3"""
    reference_bucket_partition = getenv("REFERENCE_BUCKET_PARTITION", "")
    source_bucket = f"{getenv('REFERENCE_BUCKET_NAME')}{PARTITION_TO_BUCKET_SUFFIX.get(reference_bucket_partition, '')}"

    custom_reference_bucket_region = getenv("CUSTOM_REFERENCE_BUCKET_REGION")
    bucket_region = (
        custom_reference_bucket_region
        if custom_reference_bucket_region
        else PARTITION_TO_BUCKET_REGION.get(reference_bucket_partition, "us-east-1")
    )
    solution_version = getenv("SOLUTION_VERSION")
    solution_tmn = getenv("SOLUTION_TMN")

    if not all([source_bucket, bucket_region, solution_tmn, solution_version]):
        missing = [
            name
            for name, value in [
                ("REFERENCE_BUCKET_NAME", source_bucket),
                ("REFERENCE_BUCKET_REGION", bucket_region),
                ("SOLUTION_TMN", solution_tmn),
                ("SOLUTION_VERSION", solution_version),
            ]
            if not value
        ]
        raise ValueError(f"Environment variables not set: {', '.join(missing)}")

    s3_client = boto3.client("s3", region_name=bucket_region, config=BOTO_CONFIG)

    try:
        response = s3_client.get_object(
            Bucket=source_bucket,
            Key=f"{solution_tmn}/{solution_version}/supported-controls.json",
        )
        content = json.loads(response["Body"].read())
        return cast(list[str], content.get("supportedControls", []))
    except Exception as e:
        logger.error(f"Failed to fetch supported controls: {e}")
        raise


BATCH_GET_CONTROLS_SIZE = 100


def get_control_descriptions(control_ids: list[str]) -> dict[str, str]:
    """Fetch control descriptions from Security Hub using BatchGetSecurityControls.

    Batches requests in groups of BATCH_GET_CONTROLS_SIZE to stay within API limits.
    Returns a mapping of controlId -> description. Controls that cannot be fetched
    are logged and omitted from the result.
    """
    if not control_ids:
        return {}

    securityhub_client = boto3.client(
        "securityhub", region_name=getenv("AWS_REGION"), config=BOTO_CONFIG
    )
    descriptions: dict[str, str] = {}

    for i in range(0, len(control_ids), BATCH_GET_CONTROLS_SIZE):
        batch = control_ids[i : i + BATCH_GET_CONTROLS_SIZE]
        try:
            response = securityhub_client.batch_get_security_controls(
                SecurityControlIds=batch
            )
            for control in response.get("SecurityControls", []):
                descriptions[control["SecurityControlId"]] = control.get(
                    "Description", ""
                )
            unprocessed = response.get("UnprocessedIds", [])
            if unprocessed:
                unprocessed_ids = [u["SecurityControlId"] for u in unprocessed]
                logger.warning(
                    f"Could not fetch descriptions for controls: {unprocessed_ids}"
                )
        except Exception as e:
            logger.error(f"Failed to fetch control descriptions from Security Hub: {e}")

    return descriptions


def get_existing_controls(table_name: str) -> list[dict[str, Any]]:
    """Get all existing control items from DynamoDB table.

    Returns full items (not just IDs) to avoid multiple scans when we need
    to check schema migration status.
    """
    dynamodb = boto3.resource(
        "dynamodb", region_name=getenv("AWS_REGION"), config=BOTO_CONFIG
    )
    table = dynamodb.Table(table_name)

    try:
        response = table.scan()
        items = list(response["Items"])

        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response["Items"])

        return items
    except Exception as e:
        logger.error(f"Failed to scan existing controls: {e}")
        raise


def populate_table(table_name: str, controls: list[str]) -> None:
    """Populate table with supported controls with new schema attributes.

    Fetches control descriptions from Security Hub via BatchGetSecurityControls.
    If descriptions cannot be fetched, controls are still created with empty descriptions.
    """
    dynamodb = boto3.resource(
        "dynamodb", region_name=getenv("AWS_REGION"), config=BOTO_CONFIG
    )
    table = dynamodb.Table(table_name)

    descriptions = get_control_descriptions(controls)

    try:
        with table.batch_writer() as batch:
            for control_id in controls:
                description = descriptions.get(control_id, "")
                batch.put_item(
                    Item=cast(
                        dict[str, Any],
                        build_default_control_item(control_id, description),
                    )
                )
        logger.info(f"Populated table with {len(controls)} controls")
    except Exception as e:
        logger.error(
            f"Failed to populate table {table_name} with {len(controls)} controls: {e}"
        )
        raise


def needs_schema_migration(item: dict[str, Any]) -> bool:
    """Check if a control item needs migration to the current supported schema.

    Returns True if any of the new schema attributes are missing.
    Note: 'filters' can be missing (treated as empty set) but other attributes are required.
    """
    required_attributes = [
        "description",
        "filterMode",
        "version",
        "lastModified",
        "modifiedBy",
    ]
    return any(attr not in item for attr in required_attributes)


def build_default_control_item(
    control_id: str, description: str = ""
) -> SecurityControlItem:
    """Build a control item with default schema values.

    Note: 'filters' is intentionally omitted when empty because DynamoDB
    does not allow empty sets. The application layer treats a missing
    'filters' attribute as an empty set.
    """
    return {
        "controlId": control_id,
        "description": description,
        "automatedRemediationEnabled": False,
        "filterMode": "include",
        "version": 1,
        "lastModified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "modifiedBy": "system",
    }


def add_new_controls(
    table: Table, control_ids: set[str], descriptions: dict[str, str]
) -> None:
    """Add new controls to the table with default schema values."""
    if not control_ids:
        return

    try:
        with table.batch_writer() as batch:
            for control_id in control_ids:
                description = descriptions.get(control_id, "")
                batch.put_item(
                    Item=cast(
                        dict[str, Any],
                        build_default_control_item(control_id, description),
                    )
                )
        logger.info(f"Added {len(control_ids)} new controls")
    except Exception as e:
        logger.error(f"Failed to add {len(control_ids)} new controls: {e}")
        raise


def migrate_controls_to_current_schema(
    table: Table, items: list[dict[str, Any]], descriptions: dict[str, str]
) -> int:
    """Migrate existing controls to the new schema, preserving all existing attribute values.

    Returns the number of items that were migrated.
    """
    items_to_migrate = [item for item in items if needs_schema_migration(item)]

    if not items_to_migrate:
        return 0

    try:
        with table.batch_writer() as batch:
            for item in items_to_migrate:
                control_id = str(item["controlId"])
                description = descriptions.get(control_id, "")
                migrated_item = build_default_control_item(control_id, description)
                migrated_item["automatedRemediationEnabled"] = item.get(
                    "automatedRemediationEnabled", False
                )
                existing_filters = item.get("filters")
                if existing_filters:
                    migrated_item["filters"] = existing_filters
                batch.put_item(Item=cast(dict[str, Any], migrated_item))
        logger.info(f"Migrated {len(items_to_migrate)} controls to new schema")
        return len(items_to_migrate)
    except Exception as e:
        logger.error(
            f"Failed to migrate {len(items_to_migrate)} controls to new schema: {e}"
        )
        raise


def update_table(table_name: str, supported_controls: list[str]) -> None:
    """Update table to add new supported controls and ensure each item follows the current supported schema.

    This function:
    1. Adds new controls from the supported controls list that don't exist in the table
    2. Preserves ALL existing controls (including custom user-added controls)
    3. Migrates existing controls to the new schema only if they don't already have it
    4. Preserves all existing attribute values (automatedRemediationEnabled, filters, etc.)
    5. Fetches descriptions from Security Hub for new and migrating controls

    """
    existing_items = get_existing_controls(table_name)
    existing_control_ids: set[str] = {str(item["controlId"]) for item in existing_items}
    supported_set = set(supported_controls)

    dynamodb = boto3.resource(
        "dynamodb", region_name=getenv("AWS_REGION"), config=BOTO_CONFIG
    )
    table = dynamodb.Table(table_name)

    to_add = supported_set - existing_control_ids

    items_needing_migration = [
        item for item in existing_items if needs_schema_migration(item)
    ]
    controls_needing_descriptions = list(to_add) + [
        str(item["controlId"]) for item in items_needing_migration
    ]
    descriptions = (
        get_control_descriptions(controls_needing_descriptions)
        if controls_needing_descriptions
        else {}
    )

    add_new_controls(table, to_add, descriptions)

    custom_controls = existing_control_ids - supported_set
    if custom_controls:
        logger.info(
            f"Preserving {len(custom_controls)} custom controls: {sorted(custom_controls)}"
        )

    migrated_count = (
        migrate_controls_to_current_schema(table, existing_items, descriptions)
        if existing_items
        else 0
    )

    if not to_add and not migrated_count:
        logger.info("No changes needed")


@event_source(data_class=CloudFormationCustomResourceEvent)  # type: ignore[untyped-decorator]
@tracer.capture_lambda_handler  # type: ignore[untyped-decorator]
def lambda_handler(
    event: CloudFormationCustomResourceEvent, context: LambdaContext
) -> None:
    """Handle the Lambda request for remediation configuration table population"""
    response_data: dict[str, str] = {}

    try:
        properties = event["ResourceProperties"]
        logger.info(json.dumps(properties))

        request_type = event["RequestType"]
        table_name = properties["TableName"]

        if request_type == "Create":
            logger.info(f"Create: Populating table {table_name}")
            supported_controls = get_supported_controls()
            populate_table(table_name, supported_controls)

        elif request_type == "Update":
            logger.info(f"Update: Updating table {table_name}")
            supported_controls = get_supported_controls()
            update_table(table_name, supported_controls)

        elif request_type == "Delete":
            logger.info(
                f"Delete: No cleanup needed for table {table_name}, table is retained on stack deletion"
            )

        else:
            raise ValueError(f"Invalid request type {request_type}")

        logger.info("Success")
        cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)

    except Exception as exc:
        cfnresponse.send(
            event,
            context,
            cfnresponse.FAILED,
            response_data,
            reason=str(exc),
        )
