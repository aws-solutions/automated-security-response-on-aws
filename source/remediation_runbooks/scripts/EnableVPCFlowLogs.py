# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import time
from typing import TYPE_CHECKING, TypedDict

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_ec2.client import EC2Client
    from mypy_boto3_logs.client import CloudWatchLogsClient
else:
    EC2Client = object
    CloudWatchLogsClient = object


class Event(TypedDict):
    Vpc: str
    RemediationRole: str
    KmsKeyArn: str
    Region: str
    AccountId: str
    Retries: int
    Wait: int


class Response(TypedDict):
    Message: str
    Status: str


class Output(TypedDict):
    Response: Response
    IamRoleArn: str
    FlowLogArn: str


def get_partition_from_region(region: str) -> str:
    """Derive AWS partition from region name."""
    if region.startswith("cn-"):
        return "aws-cn"
    elif region.startswith("us-gov"):
        return "aws-us-gov"
    else:
        return "aws"


def connect_to_logs(boto_config: Config) -> CloudWatchLogsClient:
    return boto3.client("logs", config=boto_config)


def connect_to_ec2(boto_config: Config) -> EC2Client:
    return boto3.client("ec2", config=boto_config)


def log_group_exists(client: CloudWatchLogsClient, group: str) -> int:
    try:
        log_group_verification = client.describe_log_groups(logGroupNamePrefix=group)[
            "logGroups"
        ]
        if len(log_group_verification) >= 1:
            for existing_loggroup in log_group_verification:
                if existing_loggroup["logGroupName"] == group:
                    return 1
        return 0

    except Exception as e:
        exit(f"EnableVPCFlowLogs failed - unhandled exception {str(e)}")


def wait_for_seconds(wait_interval: int) -> None:
    time.sleep(wait_interval)


def wait_for_loggroup(
    client: CloudWatchLogsClient, wait_interval: int, max_retries: int, loggroup: str
) -> None:
    attempts = 1
    while not log_group_exists(client, loggroup):
        wait_for_seconds(wait_interval)
        attempts += 1
        if attempts > max_retries:
            exit(f"Timeout waiting for log group {loggroup} to become active")


def flowlogs_active(client: EC2Client, loggroup: str) -> int:
    # searches for flow log status, filtered on unique CW Log Group created earlier
    try:
        flow_status = client.describe_flow_logs(
            DryRun=False,
            Filters=[
                {"Name": "log-group-name", "Values": [loggroup]},
            ],
        )["FlowLogs"]
        if len(flow_status) == 1 and flow_status[0]["FlowLogStatus"] == "ACTIVE":
            return 1
        else:
            return 0

    except Exception as e:
        exit(f"EnableVPCFlowLogs failed - unhandled exception {str(e)}")


def wait_for_flowlogs(
    client: EC2Client, wait_interval: int, max_retries: int, loggroup: str
) -> None:
    attempts = 1
    while not flowlogs_active(client, loggroup):
        wait_for_seconds(wait_interval)
        attempts += 1
        if attempts > max_retries:
            exit(
                f"Timeout waiting for flowlogs to log group {loggroup} to become active"
            )


def create_log_group(
    logs_client: CloudWatchLogsClient, vpc_flow_loggroup: str, kms_key_arn: str
) -> None:
    """Create CloudWatch log group for VPC Flow Logs."""
    try:
        logs_client.create_log_group(
            logGroupName=vpc_flow_loggroup, kmsKeyId=kms_key_arn
        )
    except ClientError as client_error:
        exception_type = client_error.response["Error"]["Code"]
        if exception_type == "ResourceAlreadyExistsException":
            print(f"CloudWatch Logs group {vpc_flow_loggroup} already exists")
        else:
            exit(f"ERROR CREATING LOGGROUP {vpc_flow_loggroup}: {str(exception_type)}")
    except Exception as e:
        exit(f"ERROR CREATING LOGGROUP {vpc_flow_loggroup}: {str(e)}")


def create_vpc_flow_log(
    ec2_client: EC2Client,
    remediation_role_arn: str,
    vpc_flow_loggroup: str,
    vpc_id: str,
) -> str:
    """Create VPC Flow Log and return flow log ID."""
    try:
        response = ec2_client.create_flow_logs(
            DryRun=False,
            DeliverLogsPermissionArn=remediation_role_arn,
            LogGroupName=vpc_flow_loggroup,
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="REJECT",
            LogDestinationType="cloud-watch-logs",
        )
        return response.get("FlowLogIds", [None])[0]
    except ClientError as client_error:
        exception_type = client_error.response["Error"]["Code"]
        if exception_type != "FlowLogAlreadyExists":
            exit(f"ERROR CREATING FLOW LOG: {str(exception_type)}")
        raise
    except Exception as e:
        exit(f"create_flow_logs failed {str(e)}")


def get_existing_flow_log_id(
    ec2_client: EC2Client, vpc_flow_loggroup: str, vpc_id: str
) -> str | None:
    """Get existing flow log ID for VPC."""
    flow_logs = ec2_client.describe_flow_logs(
        Filters=[
            {"Name": "log-group-name", "Values": [vpc_flow_loggroup]},
            {"Name": "resource-id", "Values": [vpc_id]},
        ]
    )
    if flow_logs.get("FlowLogs"):
        return flow_logs["FlowLogs"][0]["FlowLogId"]
    return None


def build_flow_log_arn(
    partition: str, region: str, account_id: str, flow_log_id: str
) -> str:
    """Build flow log ARN from components."""
    if flow_log_id:
        return f"arn:{partition}:ec2:{region}:{account_id}:vpc-flow-log/{flow_log_id}"
    return ""


def enable_flow_logs(event: Event, _) -> Output:
    """
    Enable VPC Flow Logs for a VPC with CloudWatch Logs destination.
    On success returns a string map with IAM role ARN and flow log ARN.
    On failure exits with error message.
    """
    max_retries = event.get("Retries", 12)
    wait_interval = event.get("Wait", 5)
    boto_config = Config(retries={"mode": "standard"})

    if "Vpc" not in event or "RemediationRole" not in event or "KmsKeyArn" not in event:
        exit("Error: missing vpc from input")

    remediation_role_arn = event["RemediationRole"]
    region = event.get("Region", "us-east-1")
    account_id = event.get("AccountId", "")
    partition = get_partition_from_region(region)
    vpc_id = event["Vpc"]
    kms_key_arn = event["KmsKeyArn"]

    logs_client = connect_to_logs(boto_config)
    ec2_client = connect_to_ec2(boto_config)

    vpc_flow_loggroup = f"VPCFlowLogs/{vpc_id}"

    create_log_group(logs_client, vpc_flow_loggroup, kms_key_arn)
    wait_for_loggroup(logs_client, wait_interval, max_retries, vpc_flow_loggroup)

    try:
        flow_log_id = create_vpc_flow_log(
            ec2_client, remediation_role_arn, vpc_flow_loggroup, vpc_id
        )
    except ClientError:
        flow_log_id = get_existing_flow_log_id(ec2_client, vpc_flow_loggroup, vpc_id)
        flow_log_arn = build_flow_log_arn(partition, region, account_id, flow_log_id)
        return {
            "Response": {
                "Message": f"VPC Flow Logs for {vpc_id} already enabled",
                "Status": "Success",
            },
            "IamRoleArn": remediation_role_arn,
            "FlowLogArn": flow_log_arn,
        }

    wait_for_flowlogs(ec2_client, wait_interval, max_retries, vpc_flow_loggroup)
    flow_log_arn = build_flow_log_arn(partition, region, account_id, flow_log_id)

    return {
        "Response": {
            "Message": f"VPC Flow Logs enabled for {vpc_id} to {vpc_flow_loggroup}",
            "Status": "Success",
        },
        "IamRoleArn": remediation_role_arn,
        "FlowLogArn": flow_log_arn,
    }
