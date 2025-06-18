# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import datetime
import json

import boto3


def default(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    else:
        raise TypeError("Incorrect HTTPResponse format.")


def verify_enable_cloudfront_default_root_object(
    cloudfront_client, cloudfront_distribution
):
    response = cloudfront_client.get_distribution_config(Id=cloudfront_distribution)
    if response["DistributionConfig"]["DefaultRootObject"]:
        return "Verification of 'EnableCloudFrontDefaultRootObject' is successful."
    error = f"VERIFICATION FAILED. DEFAULT ROOT OBJECT FOR AMAZON CLOUDFRONT DISTRIBUTION {cloudfront_distribution} IS NOT SET."
    raise RuntimeError(error)


def handler(event, _):
    cloudfront_client = boto3.client("cloudfront")
    cloudfront_distribution_arn = event["cloudfront_distribution"]
    cloudfront_distribution_id = cloudfront_distribution_arn.split("/")[1]
    response = cloudfront_client.get_distribution_config(Id=cloudfront_distribution_id)
    response["DistributionConfig"]["DefaultRootObject"] = event["root_object"]
    update_response = cloudfront_client.update_distribution(
        DistributionConfig=response["DistributionConfig"],
        Id=cloudfront_distribution_id,
        IfMatch=response["ETag"],
    )
    output = verify_enable_cloudfront_default_root_object(
        cloudfront_client, cloudfront_distribution_id
    )
    return {
        "Output": {
            "Message": output,
            "HTTPResponse": json.dumps(update_response, default=default),
        }
    }
