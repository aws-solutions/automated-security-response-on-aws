# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import time

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def update_trail_with_error_handling(event, _):
    boto_config = Config(retries={"mode": "standard", "max_attempts": 5})
    cloudtrail = boto3.client("cloudtrail", config=boto_config)

    trail_name = event["trail_name"]
    log_group_arn = event["log_group_arn"]
    cloudwatch_role_arn = event["cloudwatch_role_arn"]
    validation_result = event.get("validation_result", {})

    try:
        last_error = None
        for attempt in range(3):
            try:
                response = cloudtrail.update_trail(
                    Name=trail_name,
                    CloudWatchLogsLogGroupArn=log_group_arn,
                    CloudWatchLogsRoleArn=cloudwatch_role_arn,
                )

                return {
                    "output": {
                        "Message": f"Successfully enabled CloudWatch logging for CloudTrail: {trail_name}",
                        "TrailName": trail_name,
                        "LogGroupArn": log_group_arn,
                        "CloudWatchRoleArn": cloudwatch_role_arn,
                        "TrailArn": response.get("TrailARN"),
                        "Success": True,
                        "ValidationWarning": not validation_result.get("Valid", True),
                    }
                }

            except ClientError as e:
                last_error = e
                error_code = e.response["Error"]["Code"]

                if error_code == "InsufficientS3BucketPolicyException" and attempt < 2:
                    time.sleep(5 * (attempt + 1))
                    continue
                elif error_code in [
                    "InvalidCloudWatchLogsLogGroupArnException",
                    "InvalidCloudWatchLogsRoleArnException",
                ]:
                    break
                elif attempt < 2 and error_code in ["ServiceUnavailable", "Throttling"]:
                    time.sleep(2**attempt)
                    continue
                else:
                    break

        return {
            "output": {
                "Message": "Failed to update CloudTrail after 3 attempts",
                "TrailName": trail_name,
                "LastError": str(last_error) if last_error else "Unknown error",
                "Success": False,
                "ValidationResult": validation_result,
            }
        }

    except Exception as e:
        return {
            "output": {
                "Message": f"Unexpected error updating CloudTrail: {str(e)}",
                "TrailName": trail_name,
                "Error": str(e),
                "Success": False,
            }
        }
