# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any

import boto3
import pytest
from botocore.config import Config
from moto import mock_aws
from ResolveAutoScalingGroupLaunchSource import (
    launch_configuration_to_launch_template_data,
    resolve_auto_scaling_group_launch_source,
)

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")

# A realistic launch configuration covering the full conversion table, including a
# top-level AssociatePublicIpAddress and SecurityGroups (which together exercise the
# device-0 NIC + security-group normalization interaction).
LAUNCH_CONFIGURATION = {
    "SecurityGroups": ["sg-00000000000000000"],
    "LaunchConfigurationName": "lc-under-test",
    "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:123456789012:launchConfiguration:abc:launchConfigurationName/lc-under-test",
    "CreatedTime": "2025-01-01T00:00:00Z",
    "MetadataOptions": {
        "HttpTokens": "optional",
        "HttpEndpoint": "enabled",
        "HttpPutResponseHopLimit": 2,
    },
    "UserData": "dXNlcmRhdGE=",
    "ClassicLinkVPCId": "vpc-classic",
    "ClassicLinkVPCSecurityGroups": [],
    "BlockDeviceMappings": [
        {
            "Ebs": {
                "SnapshotId": "snap-05c65f9cd54535a5f",
                "VolumeType": "gp2",
                "Encrypted": False,
                "VolumeSize": 8,
                "DeleteOnTermination": True,
            },
            "DeviceName": "/dev/sda1",
        },
        {"NoDevice": True, "DeviceName": "/dev/sdc"},
    ],
    "IamInstanceProfile": "arn:aws:iam::123456789012:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
    "KernelId": "",
    "EbsOptimized": False,
    "KeyName": "kp-remediation-instance",
    "RamdiskId": "",
    "ImageId": "ami-025d618a66d5e032d",
    "InstanceType": "t3.micro",
    "InstanceMonitoring": {"Enabled": False},
    "PlacementTenancy": "default",
    "SpotPrice": "0.05",
    "AssociatePublicIpAddress": True,
}


def test_launch_configuration_to_launch_template_data_maps_all_fields() -> None:
    result = launch_configuration_to_launch_template_data(LAUNCH_CONFIGURATION)

    # Straight copies.
    assert result["ImageId"] == "ami-025d618a66d5e032d"
    assert result["InstanceType"] == "t3.micro"
    assert result["KeyName"] == "kp-remediation-instance"
    assert result["UserData"] == "dXNlcmRhdGE="
    assert result["EbsOptimized"] is False

    # Renames.
    assert result["Monitoring"] == {"Enabled": False}
    assert result["Placement"] == {"Tenancy": "default"}

    # IAM instance profile ARN form.
    assert result["IamInstanceProfile"] == {
        "Arn": "arn:aws:iam::123456789012:instance-profile/AmazonSSMRoleForInstancesQuickSetup"
    }

    # Security groups go to the top level (relocation is the apply step's job).
    assert result["SecurityGroupIds"] == ["sg-00000000000000000"]

    # MetadataOptions: the full customer dict is carried through unchanged by the
    # conversion. HttpPutResponseHopLimit and any other fields must not be dropped
    # before the IMDSv2 merge runs.
    assert result["MetadataOptions"] == {
        "HttpTokens": "optional",
        "HttpEndpoint": "enabled",
        "HttpPutResponseHopLimit": 2,
    }

    # Block device mappings: Ebs sub-fields and NoDevice encoding.
    assert result["BlockDeviceMappings"][0]["Ebs"]["VolumeSize"] == 8
    assert result["BlockDeviceMappings"][0]["Ebs"]["SnapshotId"] == "snap-05c65f9cd54535a5f"
    assert result["BlockDeviceMappings"][1] == {"DeviceName": "/dev/sdc", "NoDevice": ""}

    # AssociatePublicIpAddress forces a device-0 NIC.
    assert result["NetworkInterfaces"] == [
        {"DeviceIndex": 0, "AssociatePublicIpAddress": True}
    ]

    # SpotPrice maps to InstanceMarketOptions (the raw key is never copied through).
    assert result["InstanceMarketOptions"] == {
        "MarketType": "spot",
        "SpotOptions": {"MaxPrice": "0.05"},
    }

    # Empty strings and unsupported fields are dropped.
    assert "KernelId" not in result
    assert "RamdiskId" not in result
    assert "SpotPrice" not in result
    assert "ClassicLinkVPCId" not in result
    assert "LaunchConfigurationName" not in result
    assert "LaunchConfigurationARN" not in result
    assert "CreatedTime" not in result


def test_launch_configuration_with_empty_key_name_and_user_data_omits_them() -> None:
    # DescribeLaunchConfigurations returns unset KeyName and UserData as empty
    # strings. CreateLaunchTemplate rejects an empty KeyName, so empty values must be
    # omitted rather than forwarded.
    launch_configuration = dict(LAUNCH_CONFIGURATION)
    launch_configuration["KeyName"] = ""
    launch_configuration["UserData"] = ""

    result = launch_configuration_to_launch_template_data(launch_configuration)

    assert "KeyName" not in result
    assert "UserData" not in result


def test_launch_configuration_with_real_key_name_and_user_data_keeps_them() -> None:
    # A non-empty UserData is carried through unchanged (single-encoded), which the
    # end-to-end UserData encoding guard relies on.
    result = launch_configuration_to_launch_template_data(LAUNCH_CONFIGURATION)

    assert result["KeyName"] == "kp-remediation-instance"
    assert result["UserData"] == "dXNlcmRhdGE="


def test_launch_configuration_with_spot_price_sets_market_options() -> None:
    result = launch_configuration_to_launch_template_data(LAUNCH_CONFIGURATION)

    # SpotPrice (a string) becomes InstanceMarketOptions so a Spot group stays Spot.
    assert result["InstanceMarketOptions"] == {
        "MarketType": "spot",
        "SpotOptions": {"MaxPrice": "0.05"},
    }
    # The raw launch-configuration key is never copied through verbatim.
    assert "SpotPrice" not in result


def test_launch_configuration_without_spot_price_has_no_market_options() -> None:
    launch_configuration = dict(LAUNCH_CONFIGURATION)
    del launch_configuration["SpotPrice"]

    result = launch_configuration_to_launch_template_data(launch_configuration)

    assert "InstanceMarketOptions" not in result

    launch_configuration["SpotPrice"] = ""
    result = launch_configuration_to_launch_template_data(launch_configuration)

    assert "InstanceMarketOptions" not in result


def test_launch_configuration_without_public_ip_has_no_network_interface() -> None:
    launch_configuration = dict(LAUNCH_CONFIGURATION)
    del launch_configuration["AssociatePublicIpAddress"]

    result = launch_configuration_to_launch_template_data(launch_configuration)

    assert "NetworkInterfaces" not in result
    assert result["SecurityGroupIds"] == ["sg-00000000000000000"]


def test_launch_configuration_with_named_iam_instance_profile() -> None:
    launch_configuration = dict(LAUNCH_CONFIGURATION)
    launch_configuration["IamInstanceProfile"] = "AmazonSSMRoleForInstancesQuickSetup"

    result = launch_configuration_to_launch_template_data(launch_configuration)

    assert result["IamInstanceProfile"] == {
        "Name": "AmazonSSMRoleForInstancesQuickSetup"
    }


@mock_aws
def test_resolve_launch_configuration_backed_asg_by_asg_name() -> None:
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc-under-test",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
        SecurityGroups=["sg-00000000000000000"],
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lc",
        LaunchConfigurationName="lc-under-test",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "asg-lc"}, None
    )

    assert result["status"] == "ActionNeeded"
    assert len(result["targets"]) == 1
    target = result["targets"][0]
    assert target["mode"] == "LaunchConfiguration"
    assert target["old_launch_configuration_name"] == "lc-under-test"
    assert target["launch_template_data"]["ImageId"] == "ami-025d618a66d5e032d"


@mock_aws
def test_resolve_by_launch_configuration_name_finds_owning_groups() -> None:
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="shared-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    for name in ("asg-a", "asg-b"):
        autoscaling_client.create_auto_scaling_group(
            AutoScalingGroupName=name,
            LaunchConfigurationName="shared-lc",
            MinSize=0,
            MaxSize=1,
            AvailabilityZones=["us-east-1a"],
        )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "shared-lc"}, None
    )

    assert result["status"] == "ActionNeeded"
    resolved_names = {t["auto_scaling_group_name"] for t in result["targets"]}
    assert resolved_names == {"asg-a", "asg-b"}
    assert all(t["mode"] == "LaunchConfiguration" for t in result["targets"])


@mock_aws
def test_resolve_launch_configuration_not_confused_by_same_named_group() -> None:
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    # A launch configuration named "shared" is used by group "g1".
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="shared",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="g1",
        LaunchConfigurationName="shared",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )
    # A different launch configuration backs a group that happens to be named "shared".
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="other",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="shared",
        LaunchConfigurationName="other",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "shared"}, None
    )

    resolved_names = {t["auto_scaling_group_name"] for t in result["targets"]}
    # Only the group that USES the launch configuration is remediated, not the
    # Auto Scaling group that shares its name.
    assert resolved_names == {"g1"}
    assert result["targets"][0]["old_launch_configuration_name"] == "shared"


@mock_aws
def test_resolve_launch_template_backed_asg() -> None:
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-under-test",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [
                {"DeviceIndex": 0, "AssociatePublicIpAddress": True}
            ],
        },
    )["LaunchTemplate"]
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lt",
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "$Default",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "asg-lt"}, None
    )

    target = result["targets"][0]
    assert target["mode"] == "LaunchTemplate"
    assert target["launch_template_id"] == launch_template["LaunchTemplateId"]
    assert target["source_version"] == "1"
    # The group referenced the template by $Default, so that reference is preserved.
    assert target["version_reference"] == "$Default"
    assert target["from_mixed_instances_policy"] is False
    assert target["launch_template_data"]["NetworkInterfaces"][0][
        "AssociatePublicIpAddress"
    ] is True


@mock_aws
def test_resolve_launch_template_backed_asg_preserves_latest_reference() -> None:
    # A group that references its template by $Latest keeps $Latest as its version_reference so
    # Apply does not pin it to a numeric version.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-latest",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    )["LaunchTemplate"]
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lt-latest",
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "$Latest",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "asg-lt-latest"}, None
    )

    target = result["targets"][0]
    assert target["mode"] == "LaunchTemplate"
    assert target["version_reference"] == "$Latest"


@mock_aws
def test_resolve_launch_template_backed_asg_preserves_numeric_reference() -> None:
    # A group pinned to a specific numeric version keeps that number as its version_reference.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-numeric",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    )["LaunchTemplate"]
    ec2_client.create_launch_template_version(
        LaunchTemplateId=launch_template["LaunchTemplateId"],
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.small",
        },
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lt-numeric",
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "2",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "asg-lt-numeric"}, None
    )

    target = result["targets"][0]
    assert target["mode"] == "LaunchTemplate"
    assert target["source_version"] == "2"
    assert target["version_reference"] == "2"


@mock_aws
def test_resolve_mixed_instances_policy_captures_full_policy() -> None:
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-mixed",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    )["LaunchTemplate"]
    mixed_instances_policy = {
        "LaunchTemplate": {
            "LaunchTemplateSpecification": {
                "LaunchTemplateId": launch_template["LaunchTemplateId"],
                "Version": "$Default",
            },
            "Overrides": [
                {"InstanceType": "t3.micro"},
                {"InstanceType": "t3.small"},
            ],
        },
        "InstancesDistribution": {
            "OnDemandPercentageAboveBaseCapacity": 25,
            "SpotAllocationStrategy": "capacity-optimized",
        },
    }
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-mixed",
        MixedInstancesPolicy=mixed_instances_policy,
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "asg-mixed"}, None
    )

    target = result["targets"][0]
    assert target["mode"] == "LaunchTemplate"
    assert target["from_mixed_instances_policy"] is True
    assert target["version_reference"] == "$Default"
    captured = target["mixed_instances_policy"]
    assert captured["InstancesDistribution"]["OnDemandPercentageAboveBaseCapacity"] == 25
    assert len(captured["LaunchTemplate"]["Overrides"]) == 2


@mock_aws
def test_resolve_launch_configuration_with_no_groups_raises() -> None:
    # A launch configuration that exists but is used by NO Auto Scaling group
    # launches nothing, so there is nothing to migrate. The remediation must FAIL
    # rather than report success, otherwise the control runbook would run
    # UpdateFinding and mark the finding RESOLVED while the non-compliant launch
    # configuration is left in place.
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="orphan-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )

    with pytest.raises(RuntimeError, match="orphan-lc"):
        resolve_auto_scaling_group_launch_source(
            {"AutoScalingResourceId": "orphan-lc"}, None
        )


@mock_aws
def test_resolve_unknown_identifier_is_no_action_needed() -> None:
    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "does-not-exist"}, None
    )

    assert result["status"] == "NoActionNeeded"
    assert result["targets"] == []


# The tag-fallback and verify behaviors are exercised with the group constructed directly in
# the post-migration shape (on a launch template, carrying the ASR:OriginatingLaunchConfiguration
# tag) rather than by driving a moto UpdateAutoScalingGroup to clear the launch-configuration
# name, because moto does not model Auto Scaling group launch-source mutual exclusivity (it keeps
# a stale LaunchConfigurationName alongside a launch template). A faithful end-to-end sequential
# run needs LocalStack or a live account and is out of scope for this unit suite.
ORIGINATING_LC_TAG_KEY = "ASR:OriginatingLaunchConfiguration"


def _create_migrated_group(
    ec2_client: Any,
    autoscaling_client: Any,
    group_name: str,
    originating_launch_configuration_name: str,
) -> None:
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName=f"ASR-{group_name}-lt",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    )["LaunchTemplate"]
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "$Default",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
        Tags=[
            {
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
                "Key": ORIGINATING_LC_TAG_KEY,
                "Value": originating_launch_configuration_name,
                "PropagateAtLaunch": False,
            }
        ],
    )


@mock_aws
def test_resolve_surviving_launch_configuration_with_tagged_group_returns_migrated() -> None:
    # The launch configuration still exists (a non-fatal delete left it behind) but no group
    # references it; a migrated group carries the originating-launch-configuration tag. The
    # launch-configuration-exists branch consults the tag fallback and returns that group
    # instead of raising (finding 2).
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="surviving-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    _create_migrated_group(ec2_client, autoscaling_client, "asg-migrated", "surviving-lc")

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "surviving-lc"}, None
    )

    assert result["status"] == "ActionNeeded"
    resolved_names = {t["auto_scaling_group_name"] for t in result["targets"]}
    assert resolved_names == {"asg-migrated"}
    assert all(t["mode"] == "LaunchTemplate" for t in result["targets"])


@mock_aws
def test_resolve_absent_launch_configuration_with_tagged_group_returns_migrated() -> None:
    # The launch configuration is gone (a prior control migrated and deleted it); the tagged
    # migrated group is found through the gone-path tag fallback.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    _create_migrated_group(ec2_client, autoscaling_client, "asg-migrated", "gone-lc")

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "gone-lc"}, None
    )

    assert result["status"] == "ActionNeeded"
    resolved_names = {t["auto_scaling_group_name"] for t in result["targets"]}
    assert resolved_names == {"asg-migrated"}


@mock_aws
def test_resolve_mixed_state_returns_only_still_referencing_groups() -> None:
    # Some groups still reference the launch configuration and a sibling is already migrated
    # and tagged. Only the still-referencing groups are returned this run (finding 6); the
    # migrated sibling is picked up on a later run once the launch configuration is gone or
    # unreferenced.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="shared-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-still-on-lc",
        LaunchConfigurationName="shared-lc",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )
    _create_migrated_group(
        ec2_client, autoscaling_client, "asg-already-migrated", "shared-lc"
    )

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "shared-lc"}, None
    )

    resolved_names = {t["auto_scaling_group_name"] for t in result["targets"]}
    assert resolved_names == {"asg-still-on-lc"}


@mock_aws
def test_resolve_shared_launch_configuration_two_migrated_groups_returns_both() -> None:
    # A launch configuration shared by several groups: each migrated group carries the same
    # originating tag, and the gone-path tag fallback returns all of them.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    _create_migrated_group(ec2_client, autoscaling_client, "asg-one", "shared-lc")
    _create_migrated_group(ec2_client, autoscaling_client, "asg-two", "shared-lc")

    result = resolve_auto_scaling_group_launch_source(
        {"AutoScalingResourceId": "shared-lc"}, None
    )

    resolved_names = {t["auto_scaling_group_name"] for t in result["targets"]}
    assert resolved_names == {"asg-one", "asg-two"}
