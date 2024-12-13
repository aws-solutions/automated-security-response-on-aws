# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import boto3
import botocore.session
import EnableEnhancedMonitoringOnRDSInstance as remediation
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=REGION)
RDS_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "monitoring.rds.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
RDS_MONITORING_MANAGED_POLICY = (
    "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
)


def setup():
    rds_client = boto3.client("rds", config=BOTO_CONFIG)

    response = rds_client.create_db_instance(
        AllocatedStorage=5,
        DBInstanceClass="db.t2.micro",
        DBInstanceIdentifier="my-test-instance",
        Engine="mysql",
        MasterUserPassword="MyPassword",
        MasterUsername="MyUser",
    )
    return response["DBInstance"]["DBInstanceIdentifier"]


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    mocker.patch(
        "EnableEnhancedMonitoringOnRDSInstance.connect_to_service", return_value=client
    )
    return stubber


@mock_aws
def test_handler_without_enhanced_monitoring():
    db_instance_identifier = setup()

    response = remediation.handler(
        {
            "DBIdentifier": db_instance_identifier,
            "MonitoringInterval": 5,
        },
        None,
    )

    assert response["Status"] == "Failed"


def test_handler_with_enhanced_monitoring(mocker):
    db_instance_identifier = "my-test-instance"
    # Remove this stub once moto supports enhanced monitoring with describe_db_instances
    rds_stubber = setup_client_stubber("rds", "describe_db_instances", mocker)
    for _ in range(2):  # describe_db_instances is called twice
        rds_stubber.add_response(
            "describe_db_instances",
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": db_instance_identifier,
                        "MonitoringInterval": 5,
                        "DBInstanceStatus": "available",
                    }
                ],
            },
            expected_params={"DBInstanceIdentifier": "my-test-instance"},
        )

    rds_stubber.activate()
    response = remediation.handler(
        {
            "DBIdentifier": db_instance_identifier,
            "MonitoringInterval": 5,
        },
        None,
    )

    assert response["Status"] == "Success"
    assert response["DBMonitoringInterval"] == "5"
    rds_stubber.deactivate()


def test_handler_with_invalid_event():
    with pytest.raises(Exception) as e:
        remediation.handler(
            {
                "my-key": "my-val",
            },
            None,
        )
    assert re.match(
        r"Encountered error verifying enhanced monitoring on RDS Instance:",
        str(e.value),
    )
