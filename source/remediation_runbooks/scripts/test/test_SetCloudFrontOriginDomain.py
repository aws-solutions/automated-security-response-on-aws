# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config
from moto import mock_aws
from SetCloudFrontOriginDomain import lambda_handler as remediation

BOTO_CONFIG = Config(
    retries={"mode": "standard", "max_attempts": 10}, region_name="us-east-1"
)


@mock_aws
def test_update_root_distribution():
    cloudfront_client = boto3.client("cloudfront", config=BOTO_CONFIG)
    response = cloudfront_client.create_distribution(
        DistributionConfig={
            "CallerReference": "my-distribution-7-20-2",
            "Aliases": {"Quantity": 1, "Items": ["test.com"]},
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "my-origin",
                        "DomainName": "nonexistentbucket.com",
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "my-origin",
                "ViewerProtocolPolicy": "redirect-to-https",
                "DefaultTTL": 86400,
                "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
                "ForwardedValues": {
                    "QueryString": False,
                    "Cookies": {"Forward": "none"},
                    "Headers": {"Quantity": 0},
                },
                "TrustedSigners": {"Enabled": False, "Quantity": 0},
                "MinTTL": 0,
            },
            "Comment": "My CloudFront distribution",
            "Enabled": True,
        }
    )

    distribution_id = response["Distribution"]["Id"]

    # Call remediation script
    remediation(event={"Id": distribution_id}, _="")

    updated_response = cloudfront_client.get_distribution_config(Id=distribution_id)
    updated_origin_domain = updated_response["DistributionConfig"]["Origins"]["Items"][
        0
    ]["DomainName"]
    assert updated_origin_domain == "cloudfront12remediation.example"
