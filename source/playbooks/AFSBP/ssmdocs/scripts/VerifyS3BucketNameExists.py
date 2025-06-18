# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def connect_to_service(service):
    return boto3.client(service, config=boto_config)


class Response(TypedDict):
    s3_bucket_name_for_redshift_audit_logging: str


def verify_s3_bucket_name_exists(*_: Any) -> Response:
    ssm_client = connect_to_service("ssm")
    try:
        s3_bucket_name_for_audit_logging = (
            ssm_client.get_parameter(
                Name="/Solutions/SO0111/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging"
            )
            .get("Parameter", {})
            .get("Value")
        )
        return {
            "s3_bucket_name_for_redshift_audit_logging": (
                s3_bucket_name_for_audit_logging
                if s3_bucket_name_for_audit_logging
                else "NOT_AVAILABLE"
            )
        }
    except ssm_client.exceptions.ParameterNotFound:
        return {"s3_bucket_name_for_redshift_audit_logging": "NOT_AVAILABLE"}
    except Exception as e:
        raise RuntimeError(
            f"Encountered error fetching SSM parameter "
            f"/Solutions/SO0111/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging: {str(e)}"
        )
