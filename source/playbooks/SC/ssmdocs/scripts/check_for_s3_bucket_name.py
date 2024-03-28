# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config


def connect_to_config(boto_config):
    return boto3.client("config", config=boto_config)


def connect_to_ssm(boto_config):
    return boto3.client("ssm", config=boto_config)


def get_solution_id():
    return "SO0111"


def get_solution_version():
    ssm = connect_to_ssm(
        Config(
            retries={"mode": "standard"},
            user_agent_extra=f"AwsSolution/{get_solution_id()}/unknown",
        )
    )
    solution_version = "unknown"
    try:
        ssm_parm_value = ssm.get_parameter(
            Name=f"/Solutions/{get_solution_id()}/member-version"
        )["Parameter"].get("Value", "unknown")
        solution_version = ssm_parm_value
    except Exception as e:
        print(e)
        print("ERROR getting solution version")
    return solution_version


def check_for_s3_bucket_name(_, __):
    try:
        ssm = connect_to_ssm(
            Config(
                retries={"mode": "standard"},
                user_agent_extra=f"AwsSolution/{get_solution_id()}/unknown",
            )
        )
        s3_bucket_name_for_audit_logging = ssm.get_parameter(
            Name=f"/Solutions/{get_solution_id()}/afsbp/1.0.0/REDSHIFT.4/S3BucketNameForAuditLogging"
        )["Parameter"].get("Value", "unknown")
    except Exception:
        return {"s3_bucket_name_for_redshift_audit_logging": "NOT_AVAILABLE"}
    return {
        "s3_bucket_name_for_redshift_audit_logging": s3_bucket_name_for_audit_logging
    }
