# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import TypedDict

import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard"})


def connect_to_service(service):
    return boto3.client(service, config=boto_config)


class Event(TypedDict):
    MonitoringInterval: int
    DBIdentifier: str


class HandlerResponse(TypedDict):
    Status: str
    Message: str
    DBMonitoringInterval: str


def handler(event, _):
    """
    Verifies that the enhanced monitoring is enabled on the RDS Instance.
    """
    try:
        rds_client = connect_to_service("rds")
        db_instance_id = event["DBIdentifier"]
        monitoring_interval = event["MonitoringInterval"]

        rds_waiter = rds_client.get_waiter("db_instance_available")
        rds_waiter.wait(DBInstanceIdentifier=db_instance_id)

        db_instances = rds_client.describe_db_instances(
            DBInstanceIdentifier=db_instance_id
        )
        db_monitoring_interval = db_instances.get("DBInstances")[0].get(
            "MonitoringInterval"
        )

        if db_monitoring_interval == monitoring_interval:
            return {
                "Status": "Success",
                "Message": f"Verified enhanced monitoring on RDS Instance {db_instance_id}.",
                "DBMonitoringInterval": str(db_monitoring_interval),
            }
        else:
            return {
                "Status": "Failed",
                "Message": f"RDS Instance {db_instance_id} does not have correct monitoring interval.\n "
                f"Expected: {monitoring_interval}\n Actual: {db_monitoring_interval}",
                "DBMonitoringInterval": str(db_monitoring_interval),
            }
    except Exception as e:
        raise RuntimeError(
            f"Encountered error verifying enhanced monitoring on RDS Instance: {str(e)}"
        )
