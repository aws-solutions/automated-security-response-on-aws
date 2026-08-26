# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Dict, List

import boto3
import botocore.session
import EnableVPCFlowLogs as validate
import pytest
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


@pytest.fixture(autouse=True)
def patch_wait_for_seconds(mocker):
    mocker.patch("EnableVPCFlowLogs.wait_for_seconds")


# =====================================================================================
# EnableVPCFlowLogging_enable_flow_logs SUCCESS
# =====================================================================================
def test_EnableVPCFlowLogs_success(mocker):
    event = {
        "Vpc": "vpc-123412341234abcde",
        "KmsKeyArn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "RemediationRole": "remediation-role-name",
        "Region": my_region,
        "AccountId": "111111111111",
        "Retries": 1,
        "Wait": 1,  # for testing, so not waiting 60 seconds for a stub
    }

    log_group_name = "VPCFlowLogs/" + event["Vpc"]  # type: ignore[operator]
    flow_log_id = "fl-0a3f6513bef12ff9a"

    describe_log_groups_simulated_response = {
        "logGroups": [
            {
                "logGroupName": log_group_name,
                "creationTime": 1614006547370,
                "metricFilterCount": 0,
                "arn": f"arn:aws:logs:us-east-1:111111111111:log-group:{log_group_name}:*",
                "storedBytes": 36202,
            }
        ]
    }
    describe_flow_logs_simulated_response = {
        "FlowLogs": [
            {
                "CreationTime": "2020-10-27T19:37:52.871000+00:00",
                "DeliverLogsPermissionArn": f'arn:aws:iam::111111111111:role/{event["RemediationRole"]}_{my_region}',
                "DeliverLogsStatus": "SUCCESS",
                "FlowLogId": "fl-0a3f6513bef12ff9a",
                "FlowLogStatus": "ACTIVE",
                "LogGroupName": "VPCFlowLogs/vpc-0a2fff8154ab10742IQoJb3JpZ2luX2VjEMT//////////wEa",
                "ResourceId": "vpc-0a2fff8154ab10742",
                "TrafficType": "REJECT",
                "LogDestinationType": "cloud-watch-logs",
                "LogFormat": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}",
                "Tags": [],
                "MaxAggregationInterval": 600,
            }
        ]
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # LOGS
    logs_client = botocore.session.get_session().create_client(
        "logs", config=BOTO_CONFIG
    )
    logs_stubber = Stubber(logs_client)

    logs_stubber.add_response(
        "create_log_group",
        {},
        {
            "logGroupName": log_group_name,
            "kmsKeyId": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        },
    )

    logs_stubber.add_response(
        "describe_log_groups",
        describe_log_groups_simulated_response,
        {"logGroupNamePrefix": log_group_name},
    )

    logs_stubber.activate()

    # EC2
    ec2_client = botocore.session.get_session().create_client("ec2", config=BOTO_CONFIG)
    ec2_stubber = Stubber(ec2_client)

    ec2_stubber.add_response(
        "create_flow_logs",
        {"FlowLogIds": [flow_log_id]},
        {
            "DryRun": False,
            "DeliverLogsPermissionArn": event["RemediationRole"],
            "LogGroupName": "VPCFlowLogs/" + event["Vpc"],  # type: ignore[operator]
            "ResourceIds": [event["Vpc"]],
            "ResourceType": "VPC",
            "TrafficType": "REJECT",
            "LogDestinationType": "cloud-watch-logs",
        },
    )
    ec2_stubber.add_response(
        "describe_flow_logs",
        describe_flow_logs_simulated_response,
        {
            "DryRun": False,
            "Filters": [
                {"Name": "log-group-name", "Values": ["VPCFlowLogs/" + event["Vpc"]]}  # type: ignore[operator]
            ],
        },
    )

    ec2_stubber.activate()

    mocker.patch("EnableVPCFlowLogs.connect_to_logs", return_value=logs_client)
    mocker.patch("EnableVPCFlowLogs.connect_to_ec2", return_value=ec2_client)

    result = validate.enable_flow_logs(event, {})

    import re

    FLOW_LOG_ARN_PATTERN = r"^arn:(aws|aws-cn|aws-us-gov):ec2:[a-z0-9-]+:\d{12}:vpc-flow-log/fl-[a-f0-9]{17}$"

    assert result == {
        "Response": {
            "Message": f'VPC Flow Logs enabled for {event["Vpc"]} to VPCFlowLogs/{event["Vpc"]}',
            "Status": "Success",
        },
        "IamRoleArn": event["RemediationRole"],
        "FlowLogArn": f'arn:aws:ec2:{my_region}:{event["AccountId"]}:vpc-flow-log/{flow_log_id}',
    }

    # Verify IAM role ARN is returned
    assert "IamRoleArn" in result
    assert result["IamRoleArn"] == event["RemediationRole"]

    # Verify flow log ARN is returned and matches expected format
    assert "FlowLogArn" in result
    assert re.match(
        FLOW_LOG_ARN_PATTERN, result["FlowLogArn"]
    ), f"ARN format invalid: {result['FlowLogArn']}"

    logs_stubber.deactivate()
    ec2_stubber.deactivate()


# =====================================================================================
# EnableVPCFlowLogging_enable_flow_logs loggroup already exists
# =====================================================================================
def test_EnableVPCFlowLogs_loggroup_exists(mocker):
    event = {
        "Vpc": "vpc-123412341234abcde",
        "RemediationRole": "remediation-role-name",
        "KmsKeyArn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "Region": my_region,
        "AccountId": "111111111111",
        "Retries": 1,
        "Wait": 1,  # for testing, so not waiting 60 seconds for a stub
    }

    log_group_name = "VPCFlowLogs/" + event["Vpc"]  # type: ignore[operator]
    flow_log_id = "fl-0a3f6513bef12ff9a"

    describe_log_groups_simulated_response = {
        "logGroups": [
            {
                "logGroupName": log_group_name,
                "creationTime": 1614006547370,
                "metricFilterCount": 0,
                "arn": f"arn:aws:logs:us-east-1:111111111111:log-group:{log_group_name}:*",
                "storedBytes": 36202,
            }
        ]
    }
    describe_flow_logs_simulated_response = {
        "FlowLogs": [
            {
                "CreationTime": "2020-10-27T19:37:52.871000+00:00",
                "DeliverLogsPermissionArn": f'arn:aws:iam::111111111111:role/{event["RemediationRole"]}_{my_region}',
                "DeliverLogsStatus": "SUCCESS",
                "FlowLogId": "fl-0a3f6513bef12ff9a",
                "FlowLogStatus": "ACTIVE",
                "LogGroupName": "VPCFlowLogs/vpc-0a2fff8154ab10742IQoJb3JpZ2luX2VjEMT//////////wEa",
                "ResourceId": "vpc-0a2fff8154ab10742",
                "TrafficType": "REJECT",
                "LogDestinationType": "cloud-watch-logs",
                "LogFormat": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}",
                "Tags": [],
                "MaxAggregationInterval": 600,
            }
        ]
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # LOGS
    logs_client = botocore.session.get_session().create_client(
        "logs", config=BOTO_CONFIG
    )
    logs_stubber = Stubber(logs_client)

    logs_stubber.add_client_error("create_log_group", "ResourceAlreadyExistsException")

    logs_stubber.add_response(
        "describe_log_groups",
        describe_log_groups_simulated_response,
        {"logGroupNamePrefix": log_group_name},
    )

    logs_stubber.activate()

    # EC2
    ec2_client = botocore.session.get_session().create_client("ec2", config=BOTO_CONFIG)
    ec2_stubber = Stubber(ec2_client)

    ec2_stubber.add_client_error("create_flow_logs", "FlowLogAlreadyExists")

    ec2_stubber.add_response(
        "describe_flow_logs",
        describe_flow_logs_simulated_response,
        {
            "Filters": [
                {"Name": "log-group-name", "Values": [log_group_name]},
                {"Name": "resource-id", "Values": [event["Vpc"]]},
            ]
        },
    )

    ec2_stubber.activate()

    mocker.patch("EnableVPCFlowLogs.connect_to_logs", return_value=logs_client)
    mocker.patch("EnableVPCFlowLogs.connect_to_ec2", return_value=ec2_client)

    result = validate.enable_flow_logs(event, {})

    import re

    FLOW_LOG_ARN_PATTERN = r"^arn:(aws|aws-cn|aws-us-gov):ec2:[a-z0-9-]+:\d{12}:vpc-flow-log/fl-[a-f0-9]{17}$"

    assert result == {
        "Response": {
            "Message": f'VPC Flow Logs for {event["Vpc"]} already enabled',
            "Status": "Success",
        },
        "IamRoleArn": event["RemediationRole"],
        "FlowLogArn": f'arn:aws:ec2:{my_region}:{event["AccountId"]}:vpc-flow-log/{flow_log_id}',
    }

    # Verify IAM role ARN is returned when log group already exists
    assert "IamRoleArn" in result
    assert result["IamRoleArn"] == event["RemediationRole"]

    # Verify flow log ARN is returned when flow log already exists
    assert "FlowLogArn" in result
    assert re.match(
        FLOW_LOG_ARN_PATTERN, result["FlowLogArn"]
    ), f"ARN format invalid: {result['FlowLogArn']}"

    logs_stubber.deactivate()
    ec2_stubber.deactivate()


# =====================================================================================
# EnableVPCFlowLogging_enable_flow_logs FAILED TO CREATE LOGGROUP
# =====================================================================================
def test_EnableVPCFlowLogs_loggroup_fails(mocker):
    retries = 3
    event = {
        "Vpc": "vpc-123412341234abcde",
        "RemediationRole": "remediation-role-name",
        "KmsKeyArn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "Region": my_region,
        "AccountId": "111111111111",
        "Retries": retries,
        "Wait": 1,  # for testing, so not waiting 60 seconds for a stub
    }

    log_group_name = "VPCFlowLogs/" + event["Vpc"]  # type: ignore[operator]

    describe_log_groups_simulated_response: Dict[str, List[str]] = {"logGroups": []}

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # LOGS
    logs_client = botocore.session.get_session().create_client(
        "logs", config=BOTO_CONFIG
    )
    logs_stubber = Stubber(logs_client)

    logs_stubber.add_response(
        "create_log_group",
        {},
        {
            "logGroupName": log_group_name,
            "kmsKeyId": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        },
    )

    for x in range(retries):
        logs_stubber.add_response(
            "describe_log_groups",
            describe_log_groups_simulated_response,
            {"logGroupNamePrefix": log_group_name},
        )

    logs_stubber.activate()

    mocker.patch("EnableVPCFlowLogs.connect_to_logs", return_value=logs_client)
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        validate.enable_flow_logs(event, {})
    assert (
        pytest_wrapped_e.value.code
        == "Timeout waiting for log group VPCFlowLogs/vpc-123412341234abcde to become active"
    )

    logs_stubber.deactivate()


# =====================================================================================
# EnableVPCFlowLogging_enable_flow_logs FAILED TO ENABLE FLOW LOGS
# =====================================================================================
def test_EnableVPCFlowLogs_flowlogs_failed(mocker):
    retries = 3
    event = {
        "Vpc": "vpc-123412341234abcde",
        "RemediationRole": "remediation-role-name",
        "KmsKeyArn": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "Region": my_region,
        "AccountId": "111111111111",
        "Retries": retries,
        "Wait": 1,  # for testing, so not waiting 60 seconds for a stub
    }

    log_group_name = "VPCFlowLogs/" + event["Vpc"]  # type: ignore[operator]

    describe_log_groups_simulated_response = {
        "logGroups": [
            {
                "logGroupName": log_group_name,
                "creationTime": 1614006547370,
                "metricFilterCount": 0,
                "arn": f"arn:aws:logs:us-east-1:111111111111:log-group:{log_group_name}:*",
                "storedBytes": 36202,
            }
        ]
    }
    describe_flow_logs_simulated_response: Dict[str, List[str]] = {"FlowLogs": []}

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # LOGS
    logs_client = botocore.session.get_session().create_client(
        "logs", config=BOTO_CONFIG
    )
    logs_stubber = Stubber(logs_client)

    logs_stubber.add_response(
        "create_log_group",
        {},
        {
            "logGroupName": log_group_name,
            "kmsKeyId": "arn:aws:kms:us-west-2:111111111111:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        },
    )

    logs_stubber.add_response(
        "describe_log_groups",
        describe_log_groups_simulated_response,
        {"logGroupNamePrefix": log_group_name},
    )

    logs_stubber.activate()

    # EC2
    ec2_client = botocore.session.get_session().create_client("ec2", config=BOTO_CONFIG)
    ec2_stubber = Stubber(ec2_client)

    ec2_stubber.add_response(
        "create_flow_logs",
        {"FlowLogIds": ["fl-test123456789"]},
        {
            "DryRun": False,
            "DeliverLogsPermissionArn": event["RemediationRole"],
            "LogGroupName": "VPCFlowLogs/" + event["Vpc"],  # type: ignore[operator]
            "ResourceIds": [event["Vpc"]],
            "ResourceType": "VPC",
            "TrafficType": "REJECT",
            "LogDestinationType": "cloud-watch-logs",
        },
    )

    for x in range(retries):
        ec2_stubber.add_response(
            "describe_flow_logs",
            describe_flow_logs_simulated_response,
            {
                "DryRun": False,
                "Filters": [
                    {
                        "Name": "log-group-name",
                        "Values": ["VPCFlowLogs/" + event["Vpc"]],  # type: ignore[operator]
                    }
                ],
            },
        )

    ec2_stubber.activate()

    mocker.patch("EnableVPCFlowLogs.connect_to_logs", return_value=logs_client)
    mocker.patch("EnableVPCFlowLogs.connect_to_ec2", return_value=ec2_client)

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        validate.enable_flow_logs(event, {})
    assert (
        pytest_wrapped_e.value.code
        == "Timeout waiting for flowlogs to log group VPCFlowLogs/vpc-123412341234abcde to become active"
    )

    logs_stubber.deactivate()
    ec2_stubber.deactivate()
