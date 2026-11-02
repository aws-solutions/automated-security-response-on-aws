# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any

import boto3
import pytest
import ApplyLaunchTemplateToAutoScalingGroup as apply_module
from ApplyLaunchTemplateToAutoScalingGroup import (
    _delete_legacy_launch_configurations,
    apply_launch_template_to_auto_scaling_group,
    normalize_security_group_placement,
)
from botocore.config import Config
from botocore.exceptions import ClientError
from moto import mock_aws

# The tag-fallback discovery and the fail-closed verify gate are exercised at the unit/function
# level with the group constructed directly in the post-migration shape, not via a faithful
# end-to-end sequential moto run, because moto does not model Auto Scaling group launch-source
# mutual exclusivity (it keeps a stale LaunchConfigurationName alongside a launch template and
# will not naturally drop a property). A faithful sequential run needs LocalStack or a live
# account and is out of scope for this unit suite.

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")


def _context(
    targets: list[dict[str, Any]],
    status: str = "ActionNeeded",
    control_property: str = "require_imdsv2",
) -> dict[str, Any]:
    return {
        "Context": {"status": status, "targets": targets},
        "ControlProperty": control_property,
    }


def test_normalize_moves_top_level_groups_onto_device_zero() -> None:
    launch_template_data = {
        "SecurityGroupIds": ["sg-1", "sg-2"],
        "NetworkInterfaces": [
            {"DeviceIndex": 0, "Groups": ["sg-1"], "AssociatePublicIpAddress": False}
        ],
    }

    normalize_security_group_placement(launch_template_data)

    assert "SecurityGroupIds" not in launch_template_data
    # Merged and de-duplicated.
    assert launch_template_data["NetworkInterfaces"][0]["Groups"] == ["sg-1", "sg-2"]


def test_normalize_is_noop_without_network_interface() -> None:
    launch_template_data = {"SecurityGroupIds": ["sg-1"]}

    normalize_security_group_placement(launch_template_data)

    assert launch_template_data["SecurityGroupIds"] == ["sg-1"]


@mock_aws
def test_apply_launch_configuration_mode_migrates_and_deletes_lc() -> None:
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="old-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lc",
        LaunchConfigurationName="old-lc",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-lc",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "old-lc",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        },
    }

    result = apply_launch_template_to_auto_scaling_group(_context([target]), None)

    assert result["response"]["status"] == "Success"
    migration = result["response"]["results"][0]
    assert migration["mode"] == "LaunchConfiguration"
    assert migration["deleted_launch_configuration"] is True

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lc"]
    )["AutoScalingGroups"][0]
    # Setting a LaunchTemplate on the ASG switches it off the launch configuration.
    # (Real EC2 clears LaunchConfigurationName; moto leaves it set, so we assert the
    # launch template is now attached rather than that the LC name is gone.)
    assert group.get("LaunchTemplate", {}).get("LaunchTemplateId") == migration[
        "launch_template_id"
    ]

    remaining = autoscaling_client.describe_launch_configurations()[
        "LaunchConfigurations"
    ]
    assert all(lc["LaunchConfigurationName"] != "old-lc" for lc in remaining)


@mock_aws
def test_apply_launch_template_mode_creates_new_version_and_repoints() -> None:
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-source",
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

    target = {
        "auto_scaling_group_name": "asg-lt",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "from_mixed_instances_policy": False,
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [
                {"DeviceIndex": 0, "AssociatePublicIpAddress": False}
            ],
        },
    }

    # Layer onto the live $Latest (which has AssociatePublicIpAddress True) rather than the
    # resolved snapshot, so the result reflects reading $Latest and applying the control.
    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    assert migration["version"] == "2"
    assert migration["deleted_launch_configuration"] is False

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lt"]
    )["AutoScalingGroups"][0]
    assert group["LaunchTemplate"]["Version"] == "2"

    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=launch_template["LaunchTemplateId"], Versions=["2"]
    )["LaunchTemplateVersions"][0]
    assert new_version["LaunchTemplateData"]["NetworkInterfaces"][0][
        "AssociatePublicIpAddress"
    ] is False


@mock_aws
def test_apply_launch_template_mode_latest_reference_stays_on_latest() -> None:
    # version_reference="$Latest": the created version becomes latest and the group stays on
    # $Latest (not pinned to a number), and the template default is not moved.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-latest-src",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}],
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

    target = {
        "auto_scaling_group_name": "asg-lt-latest",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "version_reference": "$Latest",
        "from_mixed_instances_policy": False,
        "launch_template_data": {"ImageId": "ami-025d618a66d5e032d"},
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    # The result record still reports the concrete created version.
    assert migration["version"] == "2"

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lt-latest"]
    )["AutoScalingGroups"][0]
    # The group stays on $Latest rather than being pinned to a numeric version.
    assert group["LaunchTemplate"]["Version"] == "$Latest"

    # The template default version was not moved.
    template = ec2_client.describe_launch_templates(
        LaunchTemplateIds=[launch_template["LaunchTemplateId"]]
    )["LaunchTemplates"][0]
    assert template["DefaultVersionNumber"] == 1


@mock_aws
def test_apply_launch_template_mode_default_reference_moves_template_default() -> None:
    # version_reference="$Default": the group stays on $Default and the template default is
    # moved to the new version so the group adopts the fix through the default mechanism.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-default-src",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}],
        },
    )["LaunchTemplate"]
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lt-default",
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "$Default",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-lt-default",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "version_reference": "$Default",
        "from_mixed_instances_policy": False,
        "launch_template_data": {"ImageId": "ami-025d618a66d5e032d"},
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    assert migration["version"] == "2"

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lt-default"]
    )["AutoScalingGroups"][0]
    # The group stays on $Default rather than being pinned to a numeric version.
    assert group["LaunchTemplate"]["Version"] == "$Default"

    # The template default version moved to the newly created version, so $Default now
    # resolves to the fixed version.
    template = ec2_client.describe_launch_templates(
        LaunchTemplateIds=[launch_template["LaunchTemplateId"]]
    )["LaunchTemplates"][0]
    assert template["DefaultVersionNumber"] == 2


@mock_aws
def test_apply_launch_template_mode_numeric_reference_pins_new_version() -> None:
    # A numeric version_reference keeps the existing pin behavior: the group is pinned to the
    # newly created numeric version.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-numeric-src",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}],
        },
    )["LaunchTemplate"]
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lt-numeric",
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "1",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-lt-numeric",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "version_reference": "1",
        "from_mixed_instances_policy": False,
        "launch_template_data": {"ImageId": "ami-025d618a66d5e032d"},
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    assert migration["version"] == "2"

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lt-numeric"]
    )["AutoScalingGroups"][0]
    # Pinned to the new numeric version, matching the prior behavior for numeric references.
    assert group["LaunchTemplate"]["Version"] == "2"

    # The template default version was not moved for a numeric reference.
    template = ec2_client.describe_launch_templates(
        LaunchTemplateIds=[launch_template["LaunchTemplateId"]]
    )["LaunchTemplates"][0]
    assert template["DefaultVersionNumber"] == 1


@mock_aws
def test_apply_launch_template_mode_numeric_reference_sources_pinned_version_not_latest() -> (
    None
):
    # A group pinned to a specific numeric version whose template has a newer $Latest must have
    # its new version built from the PINNED version's config, not from $Latest's unrelated config.
    # Version 1 (pinned) carries a distinctive InstanceType the control does not touch; version 2
    # ($Latest) carries a different InstanceType. The fix must source from version 1.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-numeric-multi-src",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}],
        },
    )["LaunchTemplate"]
    # Newer $Latest (version 2) with a different InstanceType than the pinned version 1.
    ec2_client.create_launch_template_version(
        LaunchTemplateId=launch_template["LaunchTemplateId"],
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "m5.large",
            "NetworkInterfaces": [{"DeviceIndex": 0, "AssociatePublicIpAddress": True}],
        },
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lt-numeric-multi",
        LaunchTemplate={
            "LaunchTemplateId": launch_template["LaunchTemplateId"],
            "Version": "1",
        },
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    # Mirror the resolver: launch_template_data is the pinned version 1's data read back.
    pinned_data = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=launch_template["LaunchTemplateId"], Versions=["1"]
    )["LaunchTemplateVersions"][0]["LaunchTemplateData"]

    target = {
        "auto_scaling_group_name": "asg-lt-numeric-multi",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "version_reference": "1",
        "from_mixed_instances_policy": False,
        "launch_template_data": dict(pinned_data),
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    # v1, v2, then the created v3.
    assert migration["version"] == "3"

    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=launch_template["LaunchTemplateId"],
        Versions=[migration["version"]],
    )["LaunchTemplateVersions"][0]
    # Derived from the PINNED version 1 (t3.micro), NOT $Latest/version 2 (m5.large).
    assert new_version["LaunchTemplateData"]["InstanceType"] == "t3.micro"
    # This control's property was applied on top of the pinned version's config.
    assert (
        new_version["LaunchTemplateData"]["NetworkInterfaces"][0][
            "AssociatePublicIpAddress"
        ]
        is False
    )

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lt-numeric-multi"]
    )["AutoScalingGroups"][0]
    # The group is repointed to the newly created numeric version.
    assert group["LaunchTemplate"]["Version"] == migration["version"]

    # The template default version was not moved for a numeric reference.
    template = ec2_client.describe_launch_templates(
        LaunchTemplateIds=[launch_template["LaunchTemplateId"]]
    )["LaunchTemplates"][0]
    assert template["DefaultVersionNumber"] == 1


@mock_aws
def test_apply_mixed_instances_policy_preserves_distribution_and_overrides() -> None:
    # Correctness item 2: the full MixedInstancesPolicy must survive the repoint
    # with only the launch-template version changed.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-mixed",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [
                {"DeviceIndex": 0, "AssociatePublicIpAddress": True}
            ],
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

    target = {
        "auto_scaling_group_name": "asg-mixed",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "from_mixed_instances_policy": True,
        "mixed_instances_policy": mixed_instances_policy,
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "NetworkInterfaces": [
                {"DeviceIndex": 0, "AssociatePublicIpAddress": False}
            ],
        },
    }

    result = apply_launch_template_to_auto_scaling_group(_context([target]), None)
    migration = result["response"]["results"][0]
    assert migration["version"] == "2"

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-mixed"]
    )["AutoScalingGroups"][0]
    applied_policy = group["MixedInstancesPolicy"]
    distribution = applied_policy["InstancesDistribution"]
    assert distribution["OnDemandPercentageAboveBaseCapacity"] == 25
    assert distribution["SpotAllocationStrategy"] == "capacity-optimized"
    overrides = applied_policy["LaunchTemplate"]["Overrides"]
    assert [o["InstanceType"] for o in overrides] == ["t3.micro", "t3.small"]
    assert (
        applied_policy["LaunchTemplate"]["LaunchTemplateSpecification"]["Version"]
        == "2"
    )


@mock_aws
def test_apply_deletes_shared_launch_configuration_only_once() -> None:
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

    def _target(asg_name: str) -> dict[str, Any]:
        return {
            "auto_scaling_group_name": asg_name,
            "mode": "LaunchConfiguration",
            "old_launch_configuration_name": "shared-lc",
            "launch_template_data": {
                "ImageId": "ami-025d618a66d5e032d",
                "InstanceType": "t3.micro",
            },
        }

    result = apply_launch_template_to_auto_scaling_group(
        _context([_target("asg-a"), _target("asg-b")]), None
    )

    assert result["response"]["status"] == "Success"
    deletions = [r["deleted_launch_configuration"] for r in result["response"]["results"]]
    # The shared launch configuration is deleted exactly once, in the final pass that
    # runs only after both groups have been repointed. DeleteLaunchConfiguration would
    # reject the configuration while a sibling group still referenced it, so deletion
    # is credited to a single migration record rather than attempted mid-loop.
    assert sum(1 for deleted in deletions if deleted) == 1

    # Both groups now carry a launch template.
    groups = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-a", "asg-b"]
    )["AutoScalingGroups"]
    assert all(group.get("LaunchTemplate", {}).get("LaunchTemplateId") for group in groups)

    # The shared launch configuration is gone.
    remaining = autoscaling_client.describe_launch_configurations()[
        "LaunchConfigurations"
    ]
    assert all(lc["LaunchConfigurationName"] != "shared-lc" for lc in remaining)


@mock_aws
def test_delete_legacy_launch_configurations_skips_name_still_in_use() -> None:
    # No launch configuration is deleted while a group that uses it has not yet been
    # repointed: this is the final-pass guard that prevents a ResourceInUse rejection
    # when two groups share one configuration.
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="shared-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )

    targets = [
        {
            "auto_scaling_group_name": "asg-a",
            "mode": "LaunchConfiguration",
            "old_launch_configuration_name": "shared-lc",
            "launch_template_data": {},
        },
        {
            "auto_scaling_group_name": "asg-b",
            "mode": "LaunchConfiguration",
            "old_launch_configuration_name": "shared-lc",
            "launch_template_data": {},
        },
    ]

    # Only asg-a has been repointed, so asg-b still references the configuration.
    deleted = _delete_legacy_launch_configurations(
        autoscaling_client, targets, {"asg-a"}
    )

    assert deleted == set()
    remaining = autoscaling_client.describe_launch_configurations()[
        "LaunchConfigurations"
    ]
    assert any(lc["LaunchConfigurationName"] == "shared-lc" for lc in remaining)

    # Once both groups are repointed, the shared configuration is deleted once.
    deleted = _delete_legacy_launch_configurations(
        autoscaling_client, targets, {"asg-a", "asg-b"}
    )

    assert deleted == {"shared-lc"}


def test_delete_legacy_launch_configurations_swallows_delete_error() -> None:
    # A delete that raises is logged and swallowed so the remediation, which has
    # already repointed the group, still succeeds.
    class _RaisingClient:
        def delete_launch_configuration(self, **_: Any) -> None:
            raise RuntimeError("boom")

    targets = [
        {
            "auto_scaling_group_name": "asg-a",
            "mode": "LaunchConfiguration",
            "old_launch_configuration_name": "old-lc",
            "launch_template_data": {},
        }
    ]

    deleted = _delete_legacy_launch_configurations(
        _RaisingClient(), targets, {"asg-a"}
    )

    assert deleted == set()


@mock_aws
def test_apply_absent_launch_configuration_name_is_skipped() -> None:
    # A LaunchConfiguration-mode target with no legacy name (empty string) is skipped
    # in the final pass: nothing is deleted and the remediation still reports success.
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="present-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lc",
        LaunchConfigurationName="present-lc",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-lc",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    }

    result = apply_launch_template_to_auto_scaling_group(_context([target]), None)

    assert result["response"]["status"] == "Success"
    assert result["response"]["results"][0]["deleted_launch_configuration"] is False


@mock_aws
def test_apply_launch_configuration_retry_after_create_then_update_failure_succeeds() -> None:
    # A prior run created ASR-g1-lt and then failed UpdateAutoScalingGroup, leaving the
    # template behind. The retry must add a new version instead of failing on
    # InvalidLaunchTemplateName.AlreadyExistsException.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc1",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="g1",
        LaunchConfigurationName="lc1",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )
    # Simulate the leftover template from the failed prior run.
    ec2_client.create_launch_template(
        LaunchTemplateName="ASR-g1-lt",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    )

    target = {
        "auto_scaling_group_name": "g1",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "lc1",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        },
    }

    result = apply_launch_template_to_auto_scaling_group(_context([target]), None)

    assert result["response"]["status"] == "Success"
    migration = result["response"]["results"][0]
    # A new version (2) was added to the existing ASR-g1-lt template.
    assert migration["version"] == "2"

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["g1"]
    )["AutoScalingGroups"][0]
    assert group["LaunchTemplate"]["LaunchTemplateId"] == migration["launch_template_id"]
    assert group["LaunchTemplate"]["Version"] == "2"

    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=migration["launch_template_id"], Versions=["2"]
    )["LaunchTemplateVersions"][0]
    assert (
        new_version["LaunchTemplateData"]["MetadataOptions"]["HttpTokens"] == "required"
    )


def test_apply_no_action_needed_is_success_noop() -> None:
    result = apply_launch_template_to_auto_scaling_group(
        _context([], status="NoActionNeeded"), None
    )

    assert result["response"]["status"] == "Success"
    assert result["response"]["results"] == []


def test_apply_rejects_unknown_control_property() -> None:
    with pytest.raises(ValueError, match="ControlProperty"):
        apply_launch_template_to_auto_scaling_group(
            _context([], control_property="not-a-real-property"), None
        )


@mock_aws
def test_apply_layering_preserves_prior_control_property_on_reuse() -> None:
    # Clobber regression: AutoScaling.3 already created ASR-g1-lt (v1 carries
    # HttpTokens=required). AutoScaling.5's Apply (no_public_ip) in LaunchConfiguration mode
    # hits AlreadyExistsException and must layer onto $Latest so the final version carries
    # BOTH properties, not just no_public_ip rebuilt from the original launch configuration.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc1",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="g1",
        LaunchConfigurationName="lc1",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )
    ec2_client.create_launch_template(
        LaunchTemplateName="ASR-g1-lt",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        },
    )

    target = {
        "auto_scaling_group_name": "g1",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "lc1",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=migration["launch_template_id"], Versions=[migration["version"]]
    )["LaunchTemplateVersions"][0]["LaunchTemplateData"]
    assert new_version["MetadataOptions"]["HttpTokens"] == "required"
    assert new_version["NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False


@mock_aws
def test_apply_layering_on_launch_template_mode_folds_top_level_security_groups() -> None:
    # Launch-template mode: $Latest carries the other control's property (HttpTokens=required)
    # and top-level SecurityGroupIds with no NetworkInterfaces. no_public_ip Apply must layer
    # onto $Latest, preserve HttpTokens, add a DeviceIndex=0 interface with public IP disabled,
    # and fold the top-level groups onto that interface so EC2 never sees both placements.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName="lt-source",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "SecurityGroupIds": ["sg-1", "sg-2"],
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

    target = {
        "auto_scaling_group_name": "asg-lt",
        "mode": "LaunchTemplate",
        "launch_template_id": launch_template["LaunchTemplateId"],
        "source_version": "1",
        "from_mixed_instances_policy": False,
        "launch_template_data": {"ImageId": "ami-025d618a66d5e032d"},
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=launch_template["LaunchTemplateId"],
        Versions=[migration["version"]],
    )["LaunchTemplateVersions"][0]["LaunchTemplateData"]
    assert new_version["MetadataOptions"]["HttpTokens"] == "required"
    assert "SecurityGroupIds" not in new_version
    assert len(new_version["NetworkInterfaces"]) == 1
    interface = new_version["NetworkInterfaces"][0]
    assert interface["DeviceIndex"] == 0
    assert interface["AssociatePublicIpAddress"] is False
    assert interface["Groups"] == ["sg-1", "sg-2"]


@mock_aws
def test_apply_create_path_applies_property_even_when_set_step_skipped() -> None:
    # Finding 3: the create (first-run) path routes through the shared apply function via
    # _prepare_base, so even if the resolved data lacks the property (e.g. the Set step did
    # not run), the created version still carries it. The gate therefore cannot silently
    # diverge from the write path on first run.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc-fresh",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-fresh",
        LaunchConfigurationName="lc-fresh",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-fresh",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "lc-fresh",
        # No MetadataOptions: simulates the Set step not having applied the property.
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="require_imdsv2"), None
    )

    migration = result["response"]["results"][0]
    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=migration["launch_template_id"], Versions=[migration["version"]]
    )["LaunchTemplateVersions"][0]["LaunchTemplateData"]
    assert new_version["MetadataOptions"]["HttpTokens"] == "required"


@mock_aws
def test_apply_reuse_path_normalizes_top_level_security_groups() -> None:
    # Security-group normalization on the $Latest base via the reuse path (AlreadyExists): a
    # leftover ASR-g1-lt whose $Latest carries top-level SecurityGroupIds and no interfaces
    # must, after no_public_ip Apply, end with the groups folded onto the new DeviceIndex=0
    # interface and no top-level SecurityGroupIds, so CreateLaunchTemplateVersion succeeds.
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc1",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="g1",
        LaunchConfigurationName="lc1",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )
    ec2_client.create_launch_template(
        LaunchTemplateName="ASR-g1-lt",
        LaunchTemplateData={
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "SecurityGroupIds": ["sg-aaa", "sg-bbb"],
        },
    )

    target = {
        "auto_scaling_group_name": "g1",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "lc1",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="no_public_ip"), None
    )

    migration = result["response"]["results"][0]
    new_version = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=migration["launch_template_id"], Versions=[migration["version"]]
    )["LaunchTemplateVersions"][0]["LaunchTemplateData"]
    assert "SecurityGroupIds" not in new_version
    assert new_version["NetworkInterfaces"][0]["Groups"] == ["sg-aaa", "sg-bbb"]
    assert new_version["NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False


@mock_aws
def test_apply_tags_migrated_group_with_originating_launch_configuration() -> None:
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="old-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lc",
        LaunchConfigurationName="old-lc",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-lc",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "old-lc",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        },
    }

    apply_launch_template_to_auto_scaling_group(_context([target]), None)

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lc"]
    )["AutoScalingGroups"][0]
    tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
    assert tags["ASR:OriginatingLaunchConfiguration"] == "old-lc"


@mock_aws
def test_apply_tags_before_repoint(monkeypatch: pytest.MonkeyPatch) -> None:
    # Finding 1: the tag write must happen before the repoint so an untagged group is always
    # still on its launch configuration.
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="old-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lc",
        LaunchConfigurationName="old-lc",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    calls: list[str] = []
    real_tag = apply_module._tag_migrated_group
    real_repoint = apply_module._repoint_auto_scaling_group

    def tag_wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append("tag")
        return real_tag(*args, **kwargs)

    def repoint_wrapper(*args: Any, **kwargs: Any) -> Any:
        calls.append("repoint")
        return real_repoint(*args, **kwargs)

    monkeypatch.setattr(apply_module, "_tag_migrated_group", tag_wrapper)
    monkeypatch.setattr(apply_module, "_repoint_auto_scaling_group", repoint_wrapper)

    target = {
        "auto_scaling_group_name": "asg-lc",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "old-lc",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        },
    }

    apply_launch_template_to_auto_scaling_group(_context([target]), None)

    assert calls == ["tag", "repoint"]


@mock_aws
def test_apply_tag_write_failure_is_fatal_and_group_not_repointed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Finding 1: a CreateOrUpdateTags failure is fatal. Apply raises (the finding stays OPEN)
    # and the group is NOT repointed, so it is rediscovered the ordinary way on retry.
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="old-lc",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-lc",
        LaunchConfigurationName="old-lc",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    class _TagFailingAutoScaling:
        def __init__(self, real: Any) -> None:
            self._real = real

        def create_or_update_tags(self, **_: Any) -> None:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "CreateOrUpdateTags",
            )

        def __getattr__(self, name: str) -> Any:
            return getattr(self._real, name)

    wrapper = _TagFailingAutoScaling(autoscaling_client)
    monkeypatch.setattr(apply_module, "connect_to_auto_scaling", lambda _config: wrapper)

    target = {
        "auto_scaling_group_name": "asg-lc",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "old-lc",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        },
    }

    with pytest.raises(RuntimeError, match="asg-lc"):
        apply_launch_template_to_auto_scaling_group(_context([target]), None)

    group = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=["asg-lc"]
    )["AutoScalingGroups"][0]
    # The repoint never ran, so no launch template was attached.
    assert not group.get("LaunchTemplate")


@mock_aws
def test_apply_verify_gate_passes_when_property_present() -> None:
    # Verify gate positive: a normal Apply whose final template carries the property returns
    # Success (the gate runs and does not raise).
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc-ok",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-ok",
        LaunchConfigurationName="lc-ok",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    target = {
        "auto_scaling_group_name": "asg-ok",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "lc-ok",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    }

    result = apply_launch_template_to_auto_scaling_group(
        _context([target], control_property="require_imdsv2"), None
    )

    assert result["response"]["status"] == "Success"


@mock_aws
def test_apply_verify_gate_fails_closed_when_property_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Verify gate negative (function-level): force the group's effective template to lack the
    # property and assert Apply raises. moto will not naturally drop the property, so the
    # read-back is patched to return property-less data.
    autoscaling_client = boto3.client("autoscaling", config=BOTO_CONFIG)
    autoscaling_client.create_launch_configuration(
        LaunchConfigurationName="lc-bad",
        ImageId="ami-025d618a66d5e032d",
        InstanceType="t3.micro",
    )
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName="asg-bad",
        LaunchConfigurationName="lc-bad",
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=["us-east-1a"],
    )

    monkeypatch.setattr(
        apply_module,
        "_effective_launch_template_data",
        lambda *_args, **_kwargs: {"ImageId": "ami-025d618a66d5e032d"},
    )

    target = {
        "auto_scaling_group_name": "asg-bad",
        "mode": "LaunchConfiguration",
        "old_launch_configuration_name": "lc-bad",
        "launch_template_data": {
            "ImageId": "ami-025d618a66d5e032d",
            "InstanceType": "t3.micro",
        },
    }

    with pytest.raises(RuntimeError, match="asg-bad"):
        apply_launch_template_to_auto_scaling_group(
            _context([target], control_property="require_imdsv2"), None
        )
