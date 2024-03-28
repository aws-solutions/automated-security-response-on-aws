# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json

import boto3
from botocore.config import Config


def connect_to_autoscaling(boto_config):
    return boto3.client("autoscaling", config=boto_config)


def verify(event, _):
    boto_config = Config(retries={"mode": "standard"})
    asg_client = connect_to_autoscaling(boto_config)
    asg_name = event["AsgName"]
    try:
        desc_asg = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )
        if len(desc_asg["AutoScalingGroups"]) < 1:
            exit(f"No AutoScaling Group found matching {asg_name}")

        health_check = desc_asg["AutoScalingGroups"][0]["HealthCheckType"]
        print(json.dumps(desc_asg["AutoScalingGroups"][0], default=str))
        if health_check == "ELB":
            return {
                "response": {
                    "message": "Autoscaling Group health check type updated to ELB",
                    "status": "Success",
                }
            }
        else:
            return {
                "response": {
                    "message": "Autoscaling Group health check type is not ELB",
                    "status": "Failed",
                }
            }
    except Exception as e:
        exit("Exception while executing remediation: " + str(e))
