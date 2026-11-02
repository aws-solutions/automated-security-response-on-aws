# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
from typing import TYPE_CHECKING, Any, Literal, TypedDict
import boto3
from botocore.config import Config

if TYPE_CHECKING:
    from mypy_boto3_autoscaling.client import AutoScalingClient
    from mypy_boto3_ec2.client import EC2Client


def connect_to_auto_scaling(boto_config: Config) -> "AutoScalingClient":
    return boto3.client("autoscaling", config=boto_config)


def connect_to_ec2(boto_config: Config) -> "EC2Client":
    return boto3.client("ec2", config=boto_config)


# Tag Apply writes before repointing a LaunchConfiguration-mode group; a sibling control
# matches it to discover an already-migrated group. Must match the key Apply writes.
ORIGINATING_LAUNCH_CONFIGURATION_TAG_KEY = "ASR:OriginatingLaunchConfiguration"


class ResolveEvent(TypedDict):
    AutoScalingResourceId: str


class Target(TypedDict, total=False):
    auto_scaling_group_name: str
    mode: Literal["LaunchTemplate", "LaunchConfiguration"]
    launch_template_id: str
    source_version: str
    # The group's ORIGINAL launch-template version reference ("$Latest", "$Default", or a
    # numeric string). Apply preserves it so a group on $Latest or $Default is not pinned to a
    # numeric version. Set only for LaunchTemplate-mode targets.
    version_reference: str
    from_mixed_instances_policy: bool
    mixed_instances_policy: dict[str, Any]
    old_launch_configuration_name: str
    launch_template_data: dict[str, Any]


class ResolveResult(TypedDict):
    status: Literal["ActionNeeded", "NoActionNeeded"]
    targets: list[Target]


def _validate_resolve_event(event: dict[str, object]) -> ResolveEvent:
    resource_id = event.get("AutoScalingResourceId")
    if not isinstance(resource_id, str) or not resource_id.strip():
        raise ValueError(
            "Missing or invalid required parameter: AutoScalingResourceId "
            "(expected a non-empty Auto Scaling group or launch configuration name)"
        )
    return ResolveEvent(AutoScalingResourceId=resource_id)


def _boto_config() -> Config:
    return Config(retries={"mode": "standard"})


def _looks_like_arn(value: str) -> bool:
    return value.startswith("arn:")


# EbsOptimized stays on membership because its meaningful value is False, which
# truthy filtering would drop. KeyName and UserData come back from
# DescribeLaunchConfigurations as empty strings when unset, and CreateLaunchTemplate
# rejects an empty KeyName, so they use truthy filtering to omit the empty values.
_DIRECT_COPY_KEYS = ("ImageId", "InstanceType", "EbsOptimized")
_TRUTHY_COPY_KEYS = ("KernelId", "RamdiskId", "KeyName", "UserData")


def _copy_present_keys(
    launch_configuration: dict[str, Any], keys: tuple[str, ...]
) -> dict[str, Any]:
    # Mirrors `if key in launch_configuration` (membership, keeps falsy values like EbsOptimized=False).
    return {key: launch_configuration[key] for key in keys if key in launch_configuration}


def _copy_truthy_keys(
    launch_configuration: dict[str, Any], keys: tuple[str, ...]
) -> dict[str, Any]:
    # Mirrors `value = get(key); if value` (drops "" / None, e.g. empty KernelId/RamdiskId).
    return {key: launch_configuration[key] for key in keys if launch_configuration.get(key)}


def _iam_instance_profile_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    value = launch_configuration.get("IamInstanceProfile")
    if not value:
        return {}
    profile_key = "Arn" if _looks_like_arn(value) else "Name"
    return {"IamInstanceProfile": {profile_key: value}}


def _security_group_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    security_groups = launch_configuration.get("SecurityGroups")
    if not security_groups:
        return {}
    return {"SecurityGroupIds": list(security_groups)}


def _block_device_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    block_device_mappings = launch_configuration.get("BlockDeviceMappings")
    if not block_device_mappings:
        return {}
    return {
        "BlockDeviceMappings": [
            _convert_block_device_mapping(mapping) for mapping in block_device_mappings
        ]
    }


def _monitoring_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    instance_monitoring = launch_configuration.get("InstanceMonitoring")
    if not instance_monitoring or "Enabled" not in instance_monitoring:
        return {}
    return {"Monitoring": {"Enabled": instance_monitoring["Enabled"]}}


def _placement_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    placement_tenancy = launch_configuration.get("PlacementTenancy")
    if not placement_tenancy:
        return {}
    return {"Placement": {"Tenancy": placement_tenancy}}


def _metadata_options_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    metadata_options = launch_configuration.get("MetadataOptions")
    if not metadata_options:
        return {}
    return {"MetadataOptions": dict(metadata_options)}


def _market_options_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    # Launch configurations carry a top-level SpotPrice string; launch templates
    # express the same intent via InstanceMarketOptions. Map only when a price is
    # present so On-Demand groups stay On-Demand.
    spot_price = launch_configuration.get("SpotPrice")
    if not spot_price:
        return {}
    return {
        "InstanceMarketOptions": {
            "MarketType": "spot",
            "SpotOptions": {"MaxPrice": spot_price},
        }
    }


def _network_interface_data(launch_configuration: dict[str, Any]) -> dict[str, Any]:
    if "AssociatePublicIpAddress" not in launch_configuration:
        return {}
    return {
        "NetworkInterfaces": [
            {
                "DeviceIndex": 0,
                "AssociatePublicIpAddress": launch_configuration[
                    "AssociatePublicIpAddress"
                ],
            }
        ]
    }


def launch_configuration_to_launch_template_data(
    launch_configuration: dict[str, Any],
) -> dict[str, Any]:
    launch_template_data: dict[str, Any] = {}
    launch_template_data.update(
        _copy_present_keys(launch_configuration, _DIRECT_COPY_KEYS)
    )
    launch_template_data.update(
        _copy_truthy_keys(launch_configuration, _TRUTHY_COPY_KEYS)
    )
    launch_template_data.update(_iam_instance_profile_data(launch_configuration))
    launch_template_data.update(_security_group_data(launch_configuration))
    launch_template_data.update(_block_device_data(launch_configuration))
    launch_template_data.update(_monitoring_data(launch_configuration))
    launch_template_data.update(_placement_data(launch_configuration))
    launch_template_data.update(_metadata_options_data(launch_configuration))
    launch_template_data.update(_market_options_data(launch_configuration))
    launch_template_data.update(_network_interface_data(launch_configuration))
    return launch_template_data


def _convert_block_device_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    converted: dict[str, Any] = {}
    if "DeviceName" in mapping:
        converted["DeviceName"] = mapping["DeviceName"]
    if "VirtualName" in mapping:
        converted["VirtualName"] = mapping["VirtualName"]
    if mapping.get("NoDevice"):
        converted["NoDevice"] = ""
        return converted
    ebs = mapping.get("Ebs")
    if ebs:
        converted["Ebs"] = {
            key: ebs[key]
            for key in (
                "VolumeType",
                "VolumeSize",
                "Iops",
                "Throughput",
                "Encrypted",
                "DeleteOnTermination",
                "SnapshotId",
                "KmsKeyId",
            )
            if key in ebs
        }
    return converted


def _resolve_launch_template_version(
    ec2_client: "EC2Client", launch_template_id: str, version: str
) -> tuple[str, dict[str, Any]]:
    response = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=launch_template_id, Versions=[version]
    )
    versions = response.get("LaunchTemplateVersions", [])
    if not versions:
        raise RuntimeError(
            f"Launch template {launch_template_id} version {version} was not found"
        )
    resolved = versions[0]
    return str(resolved["VersionNumber"]), dict(resolved["LaunchTemplateData"])


def _is_launch_configuration(
    auto_scaling_client: "AutoScalingClient", resource_id: str
) -> bool:
    return bool(
        auto_scaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[resource_id]
        ).get("LaunchConfigurations", [])
    )


def _groups_using_launch_configuration(
    auto_scaling_client: "AutoScalingClient", resource_id: str
) -> list[dict[str, Any]]:
    matching: list[dict[str, Any]] = []
    paginator = auto_scaling_client.get_paginator("describe_auto_scaling_groups")
    for page in paginator.paginate():
        for group in page["AutoScalingGroups"]:
            if group.get("LaunchConfigurationName") == resource_id:
                matching.append(group)
    return matching


def _groups_migrated_from_launch_configuration(
    auto_scaling_client: "AutoScalingClient", resource_id: str
) -> list[dict[str, Any]]:
    # Groups a prior control already migrated, found by the ASR:OriginatingLaunchConfiguration
    # tag Apply writes before repointing (exact match; tags come back inline on Describe).
    matching: list[dict[str, Any]] = []
    paginator = auto_scaling_client.get_paginator("describe_auto_scaling_groups")
    for page in paginator.paginate():
        for group in page["AutoScalingGroups"]:
            for tag in group.get("Tags", []):
                if (
                    tag.get("Key") == ORIGINATING_LAUNCH_CONFIGURATION_TAG_KEY
                    and tag.get("Value") == resource_id
                ):
                    matching.append(group)
                    break
    return matching


def _get_target_groups(
    auto_scaling_client: "AutoScalingClient", resource_id: str
) -> list[dict[str, Any]]:
    # AutoScaling.3 / Autoscaling.5 findings name a launch configuration, and the
    # resolver only receives the bare name. When a launch configuration with this
    # name exists, remediate the groups that USE it rather than an Auto Scaling
    # group that happens to share the name.
    if _is_launch_configuration(auto_scaling_client, resource_id):
        groups = _groups_using_launch_configuration(auto_scaling_client, resource_id)
        if groups:
            return groups
        # LC exists but unreferenced (a non-fatal _delete_legacy_launch_configurations can
        # leave it behind): consult the tag fallback before raising so a tagged, already-migrated
        # group is still remediated (finding 2).
        migrated = _groups_migrated_from_launch_configuration(
            auto_scaling_client, resource_id
        )
        if migrated:
            return migrated
        # Truly unused and never migrated (no tagged group): fail rather than report success,
        # which would let the runbook mark the finding RESOLVED with the LC left untouched.
        raise RuntimeError(
            f"Launch configuration {resource_id} is not used by any Auto Scaling "
            "group, so there is nothing to remediate and the finding must stay open."
        )
    direct = auto_scaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[resource_id]
    ).get("AutoScalingGroups", [])
    if direct:
        return list(direct)
    groups = _groups_using_launch_configuration(auto_scaling_client, resource_id)
    if groups:
        return groups
    # The launch configuration is gone (a prior control migrated and deleted it): find the
    # already-migrated group by its originating-launch-configuration tag.
    return _groups_migrated_from_launch_configuration(auto_scaling_client, resource_id)


def _build_target(
    auto_scaling_client: "AutoScalingClient",
    ec2_client: "EC2Client",
    group: dict[str, Any],
) -> Target:
    auto_scaling_group_name = group["AutoScalingGroupName"]
    mixed_instances_policy = group.get("MixedInstancesPolicy")
    if mixed_instances_policy:
        specification = mixed_instances_policy["LaunchTemplate"][
            "LaunchTemplateSpecification"
        ]
        launch_template_id = specification["LaunchTemplateId"]
        # An absent Version resolves to "$Default", matching the resolution below.
        version_reference = specification.get("Version") or "$Default"
        source_version, launch_template_data = _resolve_launch_template_version(
            ec2_client, launch_template_id, version_reference
        )
        return Target(
            auto_scaling_group_name=auto_scaling_group_name,
            mode="LaunchTemplate",
            launch_template_id=launch_template_id,
            source_version=source_version,
            version_reference=version_reference,
            from_mixed_instances_policy=True,
            mixed_instances_policy=mixed_instances_policy,
            launch_template_data=launch_template_data,
        )
    launch_template = group.get("LaunchTemplate")
    if launch_template:
        launch_template_id = launch_template["LaunchTemplateId"]
        # An absent Version resolves to "$Default", matching the resolution below.
        version_reference = launch_template.get("Version") or "$Default"
        source_version, launch_template_data = _resolve_launch_template_version(
            ec2_client, launch_template_id, version_reference
        )
        return Target(
            auto_scaling_group_name=auto_scaling_group_name,
            mode="LaunchTemplate",
            launch_template_id=launch_template_id,
            source_version=source_version,
            version_reference=version_reference,
            from_mixed_instances_policy=False,
            launch_template_data=launch_template_data,
        )
    launch_configuration_name = group.get("LaunchConfigurationName")
    if launch_configuration_name:
        launch_configuration = auto_scaling_client.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        ).get("LaunchConfigurations", [])
        if not launch_configuration:
            raise RuntimeError(
                f"Launch configuration {launch_configuration_name} referenced by "
                f"Auto Scaling group {auto_scaling_group_name} was not found"
            )
        return Target(
            auto_scaling_group_name=auto_scaling_group_name,
            mode="LaunchConfiguration",
            old_launch_configuration_name=launch_configuration_name,
            launch_template_data=launch_configuration_to_launch_template_data(
                launch_configuration[0]
            ),
        )
    raise RuntimeError(
        f"Auto Scaling group {auto_scaling_group_name} has no launch configuration "
        "or launch template"
    )


def resolve_auto_scaling_group_launch_source(
    event: dict[str, object], _: Any
) -> ResolveResult:
    validated = _validate_resolve_event(event)
    boto_config = _boto_config()
    auto_scaling_client = connect_to_auto_scaling(boto_config)
    ec2_client = connect_to_ec2(boto_config)
    resource_id = validated["AutoScalingResourceId"]
    groups = _get_target_groups(auto_scaling_client, resource_id)
    if not groups:
        return ResolveResult(status="NoActionNeeded", targets=[])
    targets = [
        _build_target(auto_scaling_client, ec2_client, group) for group in groups
    ]
    return ResolveResult(status="ActionNeeded", targets=targets)
