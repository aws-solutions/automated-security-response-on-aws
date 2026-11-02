# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re
from typing import TYPE_CHECKING, Literal, TypedDict

import boto3
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_s3.client import S3Client

# Intentionally invalid special-use TLD
NEW_ORIGIN_DOMAIN = "cloudfront12remediation.example"


class RemediationEvent(TypedDict):
    Id: str


class RemediationOutput(TypedDict):
    message: str
    status: Literal["Success"]


def bucket_exists(s3_client: "S3Client", domain_name: str) -> bool:
    # Greedy keeps a bucket name containing ".s3" whole; access points are skipped
    match = re.match(r"(.+)\.s3[.-](?!accesspoint|global)", domain_name, re.IGNORECASE)
    if not match:
        return True
    try:
        s3_client.head_bucket(Bucket=match.group(1).lower())
    except ClientError as error:
        error_code = error.response["Error"]["Code"]
        if error_code == "404":
            return False
        if error_code != "403":
            raise
    return True


def lambda_handler(event: RemediationEvent, _: object) -> RemediationOutput:
    cloudfront_client = boto3.client("cloudfront")
    s3_client = boto3.client("s3")
    distribution_id = event["Id"]

    response = cloudfront_client.get_distribution_config(Id=distribution_id)
    config = response["DistributionConfig"]

    # CloudFront.12 only evaluates S3 REST origins
    updated_origin_ids = []
    for origin in config["Origins"]["Items"]:
        if "S3OriginConfig" in origin and not bucket_exists(
            s3_client, origin["DomainName"]
        ):
            origin["DomainName"] = NEW_ORIGIN_DOMAIN
            del origin["S3OriginConfig"]
            origin["OriginAccessControlId"] = ""
            origin["CustomOriginConfig"] = {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            }
            updated_origin_ids.append(origin["Id"])

    if not updated_origin_ids:
        raise RuntimeError(
            f"No S3 origin on distribution {distribution_id} points to a missing bucket."
        )

    cloudfront_client.update_distribution(
        DistributionConfig=config, Id=distribution_id, IfMatch=response["ETag"]
    )
    return {
        "message": f"Updated origins: {', '.join(updated_origin_ids)}",
        "status": "Success",
    }
