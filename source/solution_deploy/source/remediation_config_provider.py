# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Custom resource provider for populating remediation configuration DynamoDB table"""

import json
from os import getenv
from typing import Dict, List, Set, cast

import boto3
import cfnresponse
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
    event_source,
)
from aws_lambda_powertools.utilities.typing import LambdaContext
from layer.powertools_logger import get_logger
from layer.tracer_utils import init_tracer

# initialize logger
LOG_LEVEL = getenv("POWERTOOLS_LOG_LEVEL", "info")
logger = get_logger("remediation_config_provider", LOG_LEVEL)
tracer = init_tracer()

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


def get_supported_controls() -> List[str]:
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

    s3_client = boto3.client("s3", region_name=bucket_region)

    try:
        response = s3_client.get_object(
            Bucket=source_bucket,
            Key=f"{solution_tmn}/{solution_version}/supported-controls.json",
        )
        content = json.loads(response["Body"].read())
        return cast(List[str], content.get("supportedControls", []))
    except Exception as e:
        logger.error(f"Failed to fetch supported controls: {e}")
        raise


def get_existing_controls(table_name: str) -> Set[str]:
    """Get existing control IDs from DynamoDB table"""
    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table(table_name)

    try:
        response = table.scan(ProjectionExpression="controlId")
        existing_controls = {item["controlId"] for item in response["Items"]}

        # Handle pagination
        while "LastEvaluatedKey" in response:
            response = table.scan(
                ProjectionExpression="controlId",
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            existing_controls.update(item["controlId"] for item in response["Items"])

        return existing_controls
    except Exception as e:
        logger.error(f"Failed to scan existing controls: {e}")
        raise


def populate_table(table_name: str, controls: List[str]) -> None:
    """Populate table with supported controls"""
    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table(table_name)

    with table.batch_writer() as batch:
        for control_id in controls:
            batch.put_item(
                Item={"controlId": control_id, "automatedRemediationEnabled": False}
            )

    logger.info(f"Populated table with {len(controls)} controls")


def update_table(table_name: str, supported_controls: List[str]) -> None:
    """Update table to match supported controls"""
    existing_controls = get_existing_controls(table_name)
    supported_set = set(supported_controls)

    # Controls to add
    to_add = supported_set - existing_controls
    # Controls to remove
    to_remove = existing_controls - supported_set

    dynamodb = boto3.resource("dynamodb", region_name=getenv("AWS_REGION"))
    table = dynamodb.Table(table_name)

    if to_add:
        with table.batch_writer() as batch:
            for control_id in to_add:
                batch.put_item(
                    Item={"controlId": control_id, "automatedRemediationEnabled": False}
                )
        logger.info(f"Added {len(to_add)} new controls")

    if to_remove:
        with table.batch_writer() as batch:
            for control_id in to_remove:
                batch.delete_item(Key={"controlId": control_id})
        logger.info(f"Removed {len(to_remove)} obsolete controls")

    if not to_add and not to_remove:
        logger.info("No changes needed")


@event_source(data_class=CloudFormationCustomResourceEvent)  # type: ignore[misc]
@tracer.capture_lambda_handler  # type: ignore[misc]
def lambda_handler(
    event: CloudFormationCustomResourceEvent, context: LambdaContext
) -> None:
    """Handle the Lambda request for remediation configuration table population"""
    response_data: Dict[str, str] = {}

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
