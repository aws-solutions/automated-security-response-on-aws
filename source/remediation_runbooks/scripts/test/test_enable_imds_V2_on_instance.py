# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `enable_imds_v2_on_instance` remediation script"""

from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from enable_imds_v2_on_instance import lambda_handler

if TYPE_CHECKING:
    from mypy_boto3_ec2.client import EC2Client
    from mypy_boto3_ec2.type_defs import DescribeInstancesResultTypeDef
else:
    DescribeInstancesResultTypeDef = object


def test_enable_imds_v2_on_instance(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    ec2: EC2Client = boto3.client("ec2", config=BOTO_CONFIG)
    stub_ec2 = Stubber(ec2)
    clients = {"ec2": ec2}

    instance_arn = (
        "arn:aws:ec2:us-east-1:111111111111:instance/instance-017e22c0195eb5ded"
    )

    instance_id = "instance-017e22c0195eb5ded"

    stub_ec2.add_response(
        "modify_instance_metadata_options",
        {},
        {
            "InstanceId": instance_id,
            "HttpTokens": "required",
            "HttpEndpoint": "enabled",
        },
    )

    stub_ec2.add_response(
        "describe_instances", describedInstance, {"InstanceIds": [instance_id]}
    )

    stub_ec2.activate()

    metadata_options = describedInstance["Reservations"][0]["Instances"][0][
        "MetadataOptions"
    ]

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"instance_arn": instance_arn}
        response = lambda_handler(event, {})
        assert response == metadata_options


describedInstance: DescribeInstancesResultTypeDef = {
    "Reservations": [
        {
            "Groups": [
                {"GroupName": "string", "GroupId": "string"},
            ],
            "Instances": [
                {
                    "AmiLaunchIndex": 123,
                    "ImageId": "string",
                    "InstanceId": "string",
                    "InstanceType": "m7i-flex.8xlarge",
                    "KernelId": "string",
                    "KeyName": "string",
                    "LaunchTime": datetime(2015, 1, 1),
                    "Monitoring": {"State": "pending"},
                    "Placement": {
                        "AvailabilityZone": "string",
                        "Affinity": "string",
                        "GroupName": "string",
                        "PartitionNumber": 123,
                        "HostId": "string",
                        "Tenancy": "host",
                        "SpreadDomain": "string",
                        "HostResourceGroupArn": "string",
                        "GroupId": "string",
                    },
                    "Platform": "Windows",
                    "PrivateDnsName": "string",
                    "PrivateIpAddress": "string",
                    "ProductCodes": [
                        {"ProductCodeId": "string", "ProductCodeType": "marketplace"},
                    ],
                    "PublicDnsName": "string",
                    "PublicIpAddress": "string",
                    "RamdiskId": "string",
                    "State": {"Code": 123, "Name": "stopped"},
                    "StateTransitionReason": "string",
                    "SubnetId": "string",
                    "VpcId": "string",
                    "Architecture": "arm64_mac",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "string",
                            "Ebs": {
                                "AttachTime": datetime(2015, 1, 1),
                                "DeleteOnTermination": False,
                                "Status": "detached",
                                "VolumeId": "string",
                            },
                        },
                    ],
                    "ClientToken": "string",
                    "EbsOptimized": False,
                    "EnaSupport": False,
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {"Arn": "string", "Id": "string"},
                    "InstanceLifecycle": "scheduled",
                    "ElasticGpuAssociations": [
                        {
                            "ElasticGpuId": "string",
                            "ElasticGpuAssociationId": "string",
                            "ElasticGpuAssociationState": "string",
                            "ElasticGpuAssociationTime": "2023-08-21T23:02:50+00:00",
                        },
                    ],
                    "ElasticInferenceAcceleratorAssociations": [
                        {
                            "ElasticInferenceAcceleratorArn": "string",
                            "ElasticInferenceAcceleratorAssociationId": "string",
                            "ElasticInferenceAcceleratorAssociationState": "string",
                            "ElasticInferenceAcceleratorAssociationTime": datetime(
                                2015, 1, 1
                            ),
                        },
                    ],
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "CarrierIp": "string",
                                "CustomerOwnedIp": "string",
                                "IpOwnerId": "string",
                                "PublicDnsName": "string",
                                "PublicIp": "string",
                            },
                            "Attachment": {
                                "AttachTime": datetime(2015, 1, 1),
                                "AttachmentId": "string",
                                "DeleteOnTermination": False,
                                "DeviceIndex": 123,
                                "Status": "detached",
                                "NetworkCardIndex": 123,
                            },
                            "Description": "string",
                            "Groups": [
                                {"GroupName": "string", "GroupId": "string"},
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "string",
                            "NetworkInterfaceId": "string",
                            "OwnerId": "string",
                            "PrivateDnsName": "string",
                            "PrivateIpAddress": "string",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "CarrierIp": "string",
                                        "CustomerOwnedIp": "string",
                                        "IpOwnerId": "string",
                                        "PublicDnsName": "string",
                                        "PublicIp": "string",
                                    },
                                    "Primary": False,
                                    "PrivateDnsName": "string",
                                    "PrivateIpAddress": "string",
                                },
                            ],
                            "SourceDestCheck": False,
                            "Status": "detaching",
                            "SubnetId": "string",
                            "VpcId": "string",
                            "InterfaceType": "string",
                            "Ipv4Prefixes": [
                                {"Ipv4Prefix": "string"},
                            ],
                            "Ipv6Prefixes": [
                                {"Ipv6Prefix": "string"},
                            ],
                        },
                    ],
                    "OutpostArn": "string",
                    "RootDeviceName": "string",
                    "RootDeviceType": "instance-store",
                    "SecurityGroups": [
                        {"GroupName": "string", "GroupId": "string"},
                    ],
                    "SourceDestCheck": False,
                    "SpotInstanceRequestId": "string",
                    "SriovNetSupport": "string",
                    "StateReason": {
                        "Code": "string",
                        "Message": "string",
                        # type: ignore[typeddict-item]
                    },
                    "Tags": [
                        {"Key": "string", "Value": "string"},
                    ],
                    "VirtualizationType": "paravirtual",
                    "CpuOptions": {"CoreCount": 123, "ThreadsPerCore": 123},
                    "CapacityReservationId": "string",
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "none",
                        "CapacityReservationTarget": {
                            "CapacityReservationId": "string",
                            "CapacityReservationResourceGroupArn": "string",
                        },
                    },
                    "HibernationOptions": {"Configured": False},
                    "Licenses": [
                        {"LicenseConfigurationArn": "string"},
                    ],
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 123,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "enabled",
                        "InstanceMetadataTags": "enabled",
                    },
                    "EnclaveOptions": {"Enabled": False},
                    "BootMode": "uefi-preferred",
                    "PlatformDetails": "string",
                    "UsageOperation": "string",
                    "UsageOperationUpdateTime": datetime(2015, 1, 1),
                    "PrivateDnsNameOptions": {
                        "HostnameType": "resource-name",
                        "EnableResourceNameDnsARecord": False,
                        "EnableResourceNameDnsAAAARecord": False,
                    },
                    "Ipv6Address": "string",
                    "TpmSupport": "string",
                    "MaintenanceOptions": {"AutoRecovery": "default"},
                    "CurrentInstanceBootMode": "uefi",
                },
            ],
            "OwnerId": "string",
            "RequesterId": "string",
            "ReservationId": "string",
        },
    ],
    "NextToken": "string",
    "ResponseMetadata": {
        "RequestId": "string",
        "HostId": "string",
        "HTTPStatusCode": 404,
        "HTTPHeaders": {},
        "RetryAttempts": 1,
    },
}
