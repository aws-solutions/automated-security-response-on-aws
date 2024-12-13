# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3


def lambda_handler(event, _):
    # Initialize the CloudFront client
    cloudfront_client = boto3.client("cloudfront")

    # The ID of the CloudFront distribution you want to update
    distribution_id = event["Id"]

    # Intentionally invalid special-use TLD
    new_origin_domain = "cloudfront12remediation.example"

    # Get the current distribution configuration
    distribution_config = cloudfront_client.get_distribution_config(Id=distribution_id)

    # Update the origin domain in the distribution configuration
    distribution_config["DistributionConfig"]["Origins"]["Items"][0][
        "DomainName"
    ] = new_origin_domain

    # Check if distribution is enabled and disable it
    if distribution_config["DistributionConfig"]["Enabled"]:
        distribution_config["DistributionConfig"]["Enabled"] = False

    # If using an S3 origin type, need to update to custom origin type
    if (
        "S3OriginConfig"
        in distribution_config["DistributionConfig"]["Origins"]["Items"][0]
    ):
        # Remove S3OriginConfig key
        del distribution_config["DistributionConfig"]["Origins"]["Items"][0][
            "S3OriginConfig"
        ]

        # Add CustomOriginConfig key
        distribution_config["DistributionConfig"]["Origins"]["Items"][0][
            "CustomOriginConfig"
        ] = {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "http-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        }

    # Update the distribution configuration
    cloudfront_client.update_distribution(
        DistributionConfig=distribution_config["DistributionConfig"],
        Id=distribution_id,
        IfMatch=distribution_config["ETag"],
    )

    updated_distribution = cloudfront_client.get_distribution_config(Id=distribution_id)
    updated_origin_domain = updated_distribution["DistributionConfig"]["Origins"][
        "Items"
    ][0]["DomainName"]

    if updated_origin_domain == "cloudfront12remediation.example":
        return {
            "message": "Origin domain updated successfully.",
            "status": "Success",
        }
    else:
        raise RuntimeError(
            "Failed to update the origin domain. Updated origin domain did not match 'cloudfront12remediation.example'"
        )
