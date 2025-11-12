# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import time
from typing import Any, Dict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def _validate_policy_statement(
    stmt: Dict[str, Any], trail_arn: str, checks: Dict[str, bool]
) -> None:
    sid = stmt.get("Sid", "")

    if (
        "AWSCloudTrailAclCheck" in sid
        and stmt.get("Effect") == "Allow"
        and stmt.get("Principal", {}).get("Service") == "cloudtrail.amazonaws.com"
        and "s3:GetBucketAcl" in stmt.get("Action", [])
        and stmt.get("Condition", {}).get("StringEquals", {}).get("AWS:SourceArn")
        == trail_arn
    ):
        checks["acl_check"] = True
    elif (
        "AWSCloudTrailWrite" in sid
        and stmt.get("Effect") == "Allow"
        and stmt.get("Principal", {}).get("Service") == "cloudtrail.amazonaws.com"
        and "s3:PutObject" in stmt.get("Action", [])
        and stmt.get("Condition", {}).get("StringEquals", {}).get("AWS:SourceArn")
        == trail_arn
    ):
        checks["put_object"] = True
    elif (
        "AllowSSLRequestsOnly" in sid
        and stmt.get("Effect") == "Deny"
        and stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
        == "false"
    ):
        checks["ssl_only"] = True


def _get_missing_statements(checks: Dict[str, bool]) -> list:
    missing = []
    if not checks["acl_check"]:
        missing.append("CloudTrail ACL check statement")
    if not checks["put_object"]:
        missing.append("CloudTrail PutObject statement")
    if not checks["ssl_only"]:
        missing.append("SSL-only enforcement statement")
    return missing


def validate_cloudtrail_policy_statements(
    policy: Dict[str, Any], trail_arn: str
) -> Dict[str, Any]:
    result = {"valid": False, "missing_statements": [], "issues": []}

    if not policy or "Statement" not in policy:
        result["issues"].append("No policy statements found")
        return result

    checks = {"acl_check": False, "put_object": False, "ssl_only": False}

    for stmt in policy["Statement"]:
        _validate_policy_statement(stmt, trail_arn, checks)

    result["missing_statements"] = _get_missing_statements(checks)
    result["valid"] = all(checks.values())
    return result


def validate_cloudtrail_bucket_policy(event, _):
    boto_config = Config(retries={"mode": "standard", "max_attempts": 3})
    s3 = boto3.client("s3", config=boto_config)
    cloudtrail = boto3.client("cloudtrail", config=boto_config)

    trail_name = event["trail_name"]

    try:
        trail_response = cloudtrail.get_trail(Name=trail_name)
        trail = trail_response["Trail"]
        bucket = trail["S3BucketName"]
        trail_arn = trail["TrailARN"]

        if not bucket or not trail_arn:
            raise ValueError(f"Trail {trail_name} missing S3 bucket or ARN")

        current_policy = None
        for attempt in range(3):
            try:
                policy_response = s3.get_bucket_policy(Bucket=bucket)
                current_policy = json.loads(policy_response["Policy"])
                break
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    return {
                        "output": {
                            "Valid": False,
                            "Message": f"No bucket policy found for {bucket}",
                            "BucketName": bucket,
                            "TrailArn": trail_arn,
                        }
                    }
                elif attempt < 2:
                    time.sleep(2)
                    continue
                else:
                    raise

        validation_result = validate_cloudtrail_policy_statements(
            current_policy, trail_arn
        )
        message = (
            "Bucket policy validation passed"
            if validation_result["valid"]
            else "Bucket policy validation failed"
        )

        if not validation_result["valid"]:
            message += (
                f". Missing: {', '.join(validation_result['missing_statements'])}"
            )
        if validation_result["issues"]:
            message += f". Issues: {', '.join(validation_result['issues'])}"

        return {
            "output": {
                "Valid": validation_result["valid"],
                "Message": message,
                "BucketName": bucket,
                "TrailArn": trail_arn,
                "MissingStatements": validation_result["missing_statements"],
                "Issues": validation_result["issues"],
            }
        }

    except Exception as e:
        return {
            "output": {
                "Valid": False,
                "Message": f"Error validating CloudTrail bucket policy: {str(e)}",
                "Error": str(e),
                "TrailName": trail_name,
            }
        }
