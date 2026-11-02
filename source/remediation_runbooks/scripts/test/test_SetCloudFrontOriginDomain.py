# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import TYPE_CHECKING

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws
from moto.cloudfront.models import cloudfront_backends
from moto.core.models import DEFAULT_ACCOUNT_ID

from SetCloudFrontOriginDomain import NEW_ORIGIN_DOMAIN, bucket_exists
from SetCloudFrontOriginDomain import lambda_handler as remediation

if TYPE_CHECKING:
    from mypy_boto3_cloudfront.type_defs import OriginOutputTypeDef, OriginTypeDef


def s3_origin(origin_id: str, domain_name: str) -> OriginTypeDef:
    return {
        "Id": origin_id,
        "DomainName": domain_name,
        "S3OriginConfig": {"OriginAccessIdentity": ""},
    }


def custom_origin(origin_id: str, domain_name: str) -> OriginTypeDef:
    return {
        "Id": origin_id,
        "DomainName": domain_name,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
        },
    }


def get_origins_by_id(distribution_id: str) -> dict[str, OriginOutputTypeDef]:
    config = boto3.client("cloudfront").get_distribution_config(Id=distribution_id)
    return {
        origin["Id"]: origin
        for origin in config["DistributionConfig"]["Origins"]["Items"]
    }


def create_distribution(origins: list[OriginTypeDef]) -> str:
    cloudfront_client = boto3.client("cloudfront")
    distribution_id: str = cloudfront_client.create_distribution(
        DistributionConfig={
            "CallerReference": "test-distribution",
            "Origins": {"Quantity": len(origins), "Items": origins},
            "DefaultCacheBehavior": {
                "TargetOriginId": origins[0]["Id"],
                "ViewerProtocolPolicy": "redirect-to-https",
                "ForwardedValues": {
                    "QueryString": False,
                    "Cookies": {"Forward": "none"},
                },
                "TrustedSigners": {"Enabled": False, "Quantity": 0},
                "MinTTL": 0,
            },
            "Comment": "",
            "Enabled": True,
        }
    )["Distribution"]["Id"]

    # moto 5.2.2 accepts S3OriginConfig but never returns it, so restore it on the stored origin
    stored_config = (
        cloudfront_backends[DEFAULT_ACCOUNT_ID]["global"]
        .distributions[distribution_id]
        .distribution_config
    )
    stored_origins = vars(stored_config)["Origins"]["Items"]
    for stored_origin, origin in zip(stored_origins, origins, strict=True):
        if "S3OriginConfig" in origin:
            stored_origin.s3_origin_config = origin["S3OriginConfig"]
    assert all(
        ("S3OriginConfig" in returned) == ("S3OriginConfig" in origin)
        for returned, origin in zip(
            get_origins_by_id(distribution_id).values(), origins, strict=True
        )
    ), "moto no longer matches the S3OriginConfig workaround"
    return distribution_id


@mock_aws
def test_replaces_only_the_origin_whose_bucket_is_missing() -> None:
    # ARRANGE
    boto3.client("s3").create_bucket(Bucket="existing-bucket")
    distribution_id = create_distribution(
        [
            custom_origin("application", "app.example.com"),
            s3_origin("existing", "existing-bucket.s3.amazonaws.com"),
            s3_origin("missing", "missing-bucket.s3.us-west-2.amazonaws.com"),
        ]
    )

    # ACT
    output = remediation(event={"Id": distribution_id}, _=None)

    # ASSERT
    origins = get_origins_by_id(distribution_id)
    assert origins["application"]["DomainName"] == "app.example.com"
    assert origins["existing"]["DomainName"] == "existing-bucket.s3.amazonaws.com"
    assert origins["missing"]["DomainName"] == NEW_ORIGIN_DOMAIN
    assert "CustomOriginConfig" in origins["missing"]
    distribution_config = boto3.client("cloudfront").get_distribution_config(
        Id=distribution_id
    )["DistributionConfig"]
    assert distribution_config["Enabled"] is True
    assert output == {"message": "Updated origins: missing", "status": "Success"}


@mock_aws
def test_fails_without_changes_when_every_bucket_exists() -> None:
    # ARRANGE
    boto3.client("s3").create_bucket(Bucket="existing-bucket")
    distribution_id = create_distribution(
        [
            custom_origin("application", "missing-bucket.s3.amazonaws.com"),
            s3_origin("existing", "existing-bucket.s3.amazonaws.com"),
        ]
    )

    # ACT / ASSERT
    with pytest.raises(RuntimeError, match="points to a missing bucket"):
        remediation(event={"Id": distribution_id}, _=None)
    origins = get_origins_by_id(distribution_id)
    assert origins["application"]["DomainName"] == "missing-bucket.s3.amazonaws.com"
    assert origins["existing"]["DomainName"] == "existing-bucket.s3.amazonaws.com"


@pytest.mark.parametrize(
    "domain_name, expected_bucket",
    [
        ("Mixed-Case.s3.amazonaws.com", "mixed-case"),
        ("bucket.s3.us-west-2.amazonaws.com", "bucket"),
        ("bucket.s3-us-west-2.amazonaws.com", "bucket"),
        ("bucket.s3-external-1.amazonaws.com", "bucket"),
        ("bucket.s3.dualstack.us-east-1.amazonaws.com", "bucket"),
        ("bucket.s3.cn-north-1.amazonaws.com.cn", "bucket"),
        ("data.s3.s3.amazonaws.com", "data.s3"),
    ],
)
@mock_aws
def test_checks_the_bucket_named_by_each_s3_domain_format(
    domain_name: str, expected_bucket: str
) -> None:
    # ARRANGE
    s3_client = boto3.client("s3")
    s3_client.create_bucket(Bucket=expected_bucket)

    # ACT
    exists = bucket_exists(s3_client, domain_name)

    # ASSERT
    assert exists is True


@pytest.mark.parametrize(
    "domain_name",
    [
        "myap-123456789012.s3-accesspoint.us-west-2.amazonaws.com",
        "mfzwi23gnjvgw.mrap.accesspoint.s3-global.amazonaws.com",
        "bucket--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com",
    ],
)
def test_treats_a_domain_that_names_no_bucket_as_existing(domain_name: str) -> None:
    # ARRANGE
    s3_client = boto3.client("s3")

    # ACT
    with Stubber(s3_client):
        exists = bucket_exists(s3_client, domain_name)

    # ASSERT
    assert exists is True


@pytest.mark.parametrize("error_code, expected_exists", [("404", False), ("403", True)])
def test_maps_head_bucket_errors_to_bucket_existence(
    error_code: str, expected_exists: bool
) -> None:
    # ARRANGE
    s3_client = boto3.client("s3")
    stubber = Stubber(s3_client)
    stubber.add_client_error("head_bucket", error_code)

    # ACT
    with stubber:
        exists = bucket_exists(s3_client, "bucket.s3.amazonaws.com")

    # ASSERT
    assert exists is expected_exists


def test_raises_on_an_unexpected_head_bucket_error() -> None:
    # ARRANGE
    s3_client = boto3.client("s3")
    stubber = Stubber(s3_client)
    stubber.add_client_error("head_bucket", "400")

    # ACT / ASSERT
    with stubber, pytest.raises(s3_client.exceptions.ClientError):
        bucket_exists(s3_client, "bucket.s3.amazonaws.com")
