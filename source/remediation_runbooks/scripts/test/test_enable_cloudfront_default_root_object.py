# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.config import Config
from enable_cloudfront_default_root_object import handler as remediation
from moto import mock_aws

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
                        "DomainName": "example.com",
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

    print(response)

    distribution_arn = response["Distribution"]["ARN"]

    distribution_id = response["Distribution"]["Id"]

    print("Fake Moto Cloudfront Distribution ID: " + distribution_id)

    print(
        "now calling remediation script with "
        + distribution_id
        + " as the target to update"
    )
    # call remediation script
    event = {
        "cloudfront_distribution": distribution_arn,
        "root_object": "index.html",
    }
    remediation(
        event,
        {},
    )

    updated_response = cloudfront_client.get_distribution(Id=distribution_id)
    updated_root_object = updated_response["Distribution"]["DistributionConfig"][
        "DefaultRootObject"
    ]
    assert updated_root_object == "index.html"
