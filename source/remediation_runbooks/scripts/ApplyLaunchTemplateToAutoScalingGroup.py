# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from mypy_boto3_autoscaling.client import AutoScalingClient
    from mypy_boto3_ec2.client import EC2Client
    from ResolveAutoScalingGroupLaunchSource import ResolveResult, Target

# Import for tests/IDE; the build strips this fence and inlines the module below. Do not remove.
# fmt: off
from common.launch_template_property import (  # noqa: E402
    NO_PUBLIC_IP,
    REQUIRE_IMDSV2,
    apply_launch_template_property,
    verify_launch_template_property,
)
# fmt: on
# %%INCLUDE=common/launch_template_property.py%%

LAUNCH_TEMPLATE_NAME_MAX_LENGTH = 128

# Symbolic launch-template version references understood by the EC2 and Auto Scaling APIs.
LATEST_VERSION = "$Latest"
DEFAULT_VERSION = "$Default"

# Tag recording the originating LC name, written before repoint so a sibling control can find
# an already-migrated group. Must match the key ResolveAutoScalingGroupLaunchSource reads.
ORIGINATING_LAUNCH_CONFIGURATION_TAG_KEY = "ASR:OriginatingLaunchConfiguration"

_KNOWN_CONTROL_PROPERTIES = (REQUIRE_IMDSV2, NO_PUBLIC_IP)


def connect_to_auto_scaling(boto_config: Config) -> "AutoScalingClient":
    return boto3.client("autoscaling", config=boto_config)


def connect_to_ec2(boto_config: Config) -> "EC2Client":
    return boto3.client("ec2", config=boto_config)


class ApplyEvent(TypedDict):
    Context: ResolveResult
    ControlProperty: str


class LaunchTemplateMigrationResult(TypedDict):
    auto_scaling_group_name: str
    launch_template_id: str
    version: str
    mode: Literal["LaunchTemplate", "LaunchConfiguration"]
    deleted_launch_configuration: bool


class ApplyResponseBody(TypedDict):
    message: str
    status: str
    results: list[LaunchTemplateMigrationResult]


class ApplyResponse(TypedDict):
    response: ApplyResponseBody


def normalize_security_group_placement(launch_template_data: dict[str, Any]) -> None:
    network_interfaces = launch_template_data.get("NetworkInterfaces")
    if not network_interfaces:
        return
    top_level_groups = launch_template_data.pop("SecurityGroupIds", None)
    if not top_level_groups:
        return
    device0 = next(
        (
            interface
            for interface in network_interfaces
            if interface.get("DeviceIndex") == 0
        ),
        network_interfaces[0],
    )
    existing = device0.get("Groups", [])
    device0["Groups"] = list(dict.fromkeys([*existing, *top_level_groups]))


def _prepare_base(
    launch_template_data: dict[str, Any], control_property: str
) -> dict[str, Any]:
    # Shared create/reuse/launch-template prep. apply MUST run before normalize so a
    # NO_PUBLIC_IP-created DeviceIndex=0 interface exists to receive folded SecurityGroupIds.
    apply_launch_template_property(launch_template_data, control_property)
    normalize_security_group_placement(launch_template_data)
    return launch_template_data


def _reuse_base_from_latest(
    ec2_client: "EC2Client",
    *,
    launch_template_id: str | None = None,
    launch_template_name: str | None = None,
    control_property: str,
) -> dict[str, Any]:
    # Layer this control's property onto live $Latest so a prior control's fix is preserved
    # instead of rebuilt from original-LC data. id and name are distinct API params: pass one.
    if (launch_template_id is None) == (launch_template_name is None):
        raise ValueError(
            "Exactly one of launch_template_id or launch_template_name is required"
        )
    selector: dict[str, Any] = (
        {"LaunchTemplateId": launch_template_id}
        if launch_template_id is not None
        else {"LaunchTemplateName": launch_template_name}
    )
    versions = ec2_client.describe_launch_template_versions(
        Versions=[LATEST_VERSION], **selector
    )["LaunchTemplateVersions"]
    if not versions:
        raise RuntimeError(
            "Launch template "
            f"{launch_template_id or launch_template_name} has no $Latest version to reuse"
        )
    base = dict(versions[0]["LaunchTemplateData"])
    return _prepare_base(base, control_property)


def _create_or_reuse_launch_template_for_lc(
    ec2_client: "EC2Client",
    launch_template_name: str,
    launch_template_data: dict[str, Any],
    control_property: str,
) -> tuple[str, str]:
    # A prior run can leave ASR-<group>-lt behind (created, then UpdateAutoScalingGroup failed).
    # On retry CreateLaunchTemplate raises AlreadyExistsException, so add a version built from
    # the existing template's $Latest (this control's property layered on), not from original-LC.
    try:
        response = ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            LaunchTemplateData=launch_template_data,
        )
        launch_template = response["LaunchTemplate"]
        return (
            launch_template["LaunchTemplateId"],
            str(launch_template["LatestVersionNumber"]),
        )
    except ClientError as error:
        if (
            error.response["Error"]["Code"]
            != "InvalidLaunchTemplateName.AlreadyExistsException"
        ):
            raise
        base = _reuse_base_from_latest(
            ec2_client,
            launch_template_name=launch_template_name,
            control_property=control_property,
        )
        version = ec2_client.create_launch_template_version(
            LaunchTemplateName=launch_template_name,
            LaunchTemplateData=base,
        )["LaunchTemplateVersion"]
        return version["LaunchTemplateId"], str(version["VersionNumber"])


def _create_or_version_launch_template(
    ec2_client: "EC2Client", target: "Target", control_property: str
) -> tuple[str, str]:
    if target["mode"] == "LaunchConfiguration":
        launch_template_name = _launch_template_name(target["auto_scaling_group_name"])
        # First-run create path: the Set-step output is authoritative only here, but it still
        # routes through _prepare_base so every path applies the property the verify gate mirrors.
        base = _prepare_base(target["launch_template_data"], control_property)
        return _create_or_reuse_launch_template_for_lc(
            ec2_client, launch_template_name, base, control_property
        )
    # Launch-template mode base selection branches on the group's original version reference.
    # Numeric pin: build the new version from the resolver's pinned-version snapshot
    # (target["launch_template_data"], resolved from the exact version the group points at) so a
    # group pinned to a specific version keeps that version's config instead of silently adopting
    # live $Latest's unrelated config. Copy the snapshot so the shared target dict is not mutated.
    # $Latest / $Default / legacy (no version_reference): layer onto live $Latest, not
    # SourceVersion, since those references intentionally track the newest or default version and
    # a concurrent control may have versioned the template since Resolve.
    version_reference = target.get("version_reference")
    if version_reference and version_reference not in (LATEST_VERSION, DEFAULT_VERSION):
        base = _prepare_base(dict(target["launch_template_data"]), control_property)
    else:
        base = _reuse_base_from_latest(
            ec2_client,
            launch_template_id=target["launch_template_id"],
            control_property=control_property,
        )
    response = ec2_client.create_launch_template_version(
        LaunchTemplateId=target["launch_template_id"],
        LaunchTemplateData=base,
    )
    version = response["LaunchTemplateVersion"]
    return version["LaunchTemplateId"], str(version["VersionNumber"])


def _resolve_repoint_version(
    ec2_client: "EC2Client", target: "Target", created_version: str
) -> str:
    # Preserve the group's original launch-template version reference so a group on $Latest or
    # $Default is not pinned to a numeric version. LaunchConfiguration mode (and any target
    # without version_reference) pins to the newly created version, which is correct because
    # that path builds a brand new ASR template.
    version_reference = target.get("version_reference")
    if not version_reference:
        return created_version
    if version_reference == LATEST_VERSION:
        # The version just created becomes $Latest, so staying on $Latest needs no extra call.
        return LATEST_VERSION
    if version_reference == DEFAULT_VERSION:
        # Move the template default to the new version so a $Default group adopts the fix while
        # staying on the default-version mechanism.
        ec2_client.modify_launch_template(
            LaunchTemplateId=target["launch_template_id"],
            DefaultVersion=created_version,
        )
        return DEFAULT_VERSION
    # The group referenced a specific numeric version, so pin it to the new numeric version.
    return created_version


def _tag_migrated_group(
    auto_scaling_client: "AutoScalingClient",
    group_name: str,
    originating_launch_configuration_name: str,
) -> None:
    # Tag before repoint so a sibling control can discover an already-migrated group. NOT the
    # fail-open common/tag_resource.py: this tag is load-bearing for the fail-closed guarantee,
    # so a write failure is FATAL and leaves the group still on its LC (rediscovered on retry).
    try:
        auto_scaling_client.create_or_update_tags(
            Tags=[
                {
                    "ResourceId": group_name,
                    "ResourceType": "auto-scaling-group",
                    "Key": ORIGINATING_LAUNCH_CONFIGURATION_TAG_KEY,
                    "Value": originating_launch_configuration_name,
                    "PropagateAtLaunch": False,
                }
            ]
        )
    except ClientError as error:
        raise RuntimeError(
            "Encountered an error tagging Auto Scaling group "
            f"{group_name} with its originating launch configuration: {str(error)}"
        )


def _launch_template_name(auto_scaling_group_name: str) -> str:
    name = f"ASR-{auto_scaling_group_name}-lt"
    return name[:LAUNCH_TEMPLATE_NAME_MAX_LENGTH]


def _repoint_auto_scaling_group(
    auto_scaling_client: "AutoScalingClient",
    target: "Target",
    launch_template_id: str,
    version: str,
) -> None:
    auto_scaling_group_name = target["auto_scaling_group_name"]
    if target.get("from_mixed_instances_policy"):
        mixed_instances_policy = target["mixed_instances_policy"]
        specification = mixed_instances_policy["LaunchTemplate"][
            "LaunchTemplateSpecification"
        ]
        specification["Version"] = version
        if "LaunchTemplateId" in specification:
            specification["LaunchTemplateId"] = launch_template_id
        auto_scaling_client.update_auto_scaling_group(
            AutoScalingGroupName=auto_scaling_group_name,
            MixedInstancesPolicy=mixed_instances_policy,
        )
        return
    auto_scaling_client.update_auto_scaling_group(
        AutoScalingGroupName=auto_scaling_group_name,
        LaunchTemplate={"LaunchTemplateId": launch_template_id, "Version": version},
    )


def _validate_apply_event(event: dict[str, object]) -> ApplyEvent:
    context = event.get("Context")
    if not isinstance(context, dict):
        raise ValueError(
            "Missing or invalid required parameter: Context "
            "(expected the resolve step output object)"
        )
    control_property = event.get("ControlProperty")
    if control_property not in _KNOWN_CONTROL_PROPERTIES:
        # Fail closed: a malformed document must not run an un-identified remediation. The
        # value drives both the write transform and the read-after-write verify gate.
        raise ValueError(
            "Missing or invalid required parameter: ControlProperty "
            f"(expected one of {_KNOWN_CONTROL_PROPERTIES})"
        )
    return ApplyEvent(
        Context=cast("ResolveResult", context),
        ControlProperty=cast(str, control_property),
    )


def _effective_launch_template_data(
    auto_scaling_client: "AutoScalingClient",
    ec2_client: "EC2Client",
    group_name: str,
) -> dict[str, Any]:
    # Re-read the group's CURRENT launch template version (not the id/version Apply just
    # created) so a concurrent repoint between our write and this read is caught.
    groups = auto_scaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[group_name]
    ).get("AutoScalingGroups", [])
    if not groups:
        raise RuntimeError(
            f"Auto Scaling group {group_name} was not found while verifying the remediation"
        )
    group = groups[0]
    specification = group.get("LaunchTemplate")
    if not specification:
        mixed_instances_policy = group.get("MixedInstancesPolicy")
        if mixed_instances_policy:
            specification = mixed_instances_policy["LaunchTemplate"][
                "LaunchTemplateSpecification"
            ]
    if not specification:
        raise RuntimeError(
            f"Auto Scaling group {group_name} has no launch template after remediation, "
            "so the remediation cannot be verified and the finding must stay open."
        )
    versions = ec2_client.describe_launch_template_versions(
        LaunchTemplateId=specification["LaunchTemplateId"],
        Versions=[specification.get("Version") or DEFAULT_VERSION],
    )["LaunchTemplateVersions"]
    if not versions:
        raise RuntimeError(
            f"Launch template version for Auto Scaling group {group_name} was not found "
            "while verifying the remediation"
        )
    return dict(versions[0]["LaunchTemplateData"])


def _verify_migrated_groups(
    auto_scaling_client: "AutoScalingClient",
    ec2_client: "EC2Client",
    migrations: list[tuple[Target, str, str]],
    control_property: str,
) -> None:
    # Fail-closed release gate: before Success, confirm each migrated group's resulting launch
    # template has this control's property; a miss raises so the Remediation step fails and the
    # finding stays OPEN. Covers every path with a target, not the NoActionNeeded short-circuit.
    for target, _launch_template_id, _version in migrations:
        group_name = target["auto_scaling_group_name"]
        effective = _effective_launch_template_data(
            auto_scaling_client, ec2_client, group_name
        )
        if not verify_launch_template_property(effective, control_property):
            raise RuntimeError(
                f"Verification failed for Auto Scaling group {group_name}: the resulting "
                f"launch template does not satisfy {control_property}, so the finding must "
                "stay open."
            )


def _legacy_launch_configuration_names(targets: list[Target]) -> list[str]:
    # Unique legacy launch configuration names, in first-seen order, for
    # LaunchConfiguration-mode targets only.
    names: list[str] = []
    for target in targets:
        if target["mode"] != "LaunchConfiguration":
            continue
        name = target.get("old_launch_configuration_name")
        if name and name not in names:
            names.append(name)
    return names


def _groups_still_referencing(
    targets: list[Target], launch_configuration_name: str, repointed: set[str]
) -> bool:
    # True while any Auto Scaling group that used this launch configuration has not
    # yet been repointed to its launch template.
    return any(
        target["mode"] == "LaunchConfiguration"
        and target.get("old_launch_configuration_name") == launch_configuration_name
        and target["auto_scaling_group_name"] not in repointed
        for target in targets
    )


def _delete_legacy_launch_configurations(
    auto_scaling_client: Any,
    targets: list[Target],
    repointed: set[str],
) -> set[str]:
    # Final pass: delete each legacy launch configuration once, only after every
    # group that used it has been repointed to its launch template.
    # DeleteLaunchConfiguration rejects a configuration still attached to a group
    # with a ResourceInUse error, so deleting mid-loop (while a sibling group still
    # references a shared configuration) would fail and leave it behind. Deletion
    # failure is non-fatal: the remediation already succeeded, so it is logged
    # rather than raised. Returns the set of names actually deleted.
    deleted_launch_configurations: set[str] = set()
    for name in _legacy_launch_configuration_names(targets):
        if _groups_still_referencing(targets, name, repointed):
            continue
        try:
            auto_scaling_client.delete_launch_configuration(
                LaunchConfigurationName=name
            )
        except Exception as error:  # noqa: BLE001
            print(f"Could not delete launch configuration {name}: {str(error)}")
            continue
        deleted_launch_configurations.add(name)
    return deleted_launch_configurations


def _credit_deletion(
    target: Target, deleted_launch_configurations: set[str], credited: set[str]
) -> bool:
    # Attribute each one-time deletion to the first LaunchConfiguration-mode target
    # that owned the name, so a shared configuration is reported deleted exactly once.
    if target["mode"] != "LaunchConfiguration":
        return False
    name = target.get("old_launch_configuration_name")
    if name in deleted_launch_configurations and name not in credited:
        credited.add(name)
        return True
    return False


def apply_launch_template_to_auto_scaling_group(
    event: dict[str, object], _: Any
) -> ApplyResponse:
    validated = _validate_apply_event(event)
    context = validated["Context"]
    control_property = validated["ControlProperty"]
    targets: list[Target] = context.get("targets", [])
    if context.get("status") == "NoActionNeeded" or not targets:
        return {
            "response": {
                "message": "No Auto Scaling group required remediation",
                "status": "Success",
                "results": [],
            }
        }
    boto_config = Config(retries={"mode": "standard"})
    auto_scaling_client = connect_to_auto_scaling(boto_config)
    ec2_client = connect_to_ec2(boto_config)
    repointed: set[str] = set()
    migrations: list[tuple[Target, str, str]] = []
    for target in targets:
        try:
            launch_template_id, version = _create_or_version_launch_template(
                ec2_client, target, control_property
            )
        except Exception as error:
            raise RuntimeError(
                "Encountered an error creating the launch template for Auto Scaling "
                f"group {target['auto_scaling_group_name']}: {str(error)}"
            )
        if target["mode"] == "LaunchConfiguration":
            # Tag before repoint (fatal): an untagged group is then always still on its LC.
            _tag_migrated_group(
                auto_scaling_client,
                target["auto_scaling_group_name"],
                target["old_launch_configuration_name"],
            )
        # Repoint the group using its preserved version reference ($Latest/$Default/numeric)
        # rather than always pinning to the created numeric version. The result record below
        # keeps reporting the concrete created version.
        repoint_version = _resolve_repoint_version(ec2_client, target, version)
        try:
            _repoint_auto_scaling_group(
                auto_scaling_client, target, launch_template_id, repoint_version
            )
        except Exception as error:
            raise RuntimeError(
                "Encountered an error updating Auto Scaling group "
                f"{target['auto_scaling_group_name']}: {str(error)}"
            )
        repointed.add(target["auto_scaling_group_name"])
        migrations.append((target, launch_template_id, version))
    # Delete legacy launch configurations only after every group has been repointed,
    # so a configuration shared by several groups is never deleted while a sibling
    # group still references it.
    deleted_launch_configurations = _delete_legacy_launch_configurations(
        auto_scaling_client, targets, repointed
    )
    # Fail-closed verify gate, AFTER the migration loop and launch-configuration deletion and
    # BEFORE the Success return: a verify failure retries down the clean tag-fallback path
    # because the launch configuration is already gone.
    _verify_migrated_groups(auto_scaling_client, ec2_client, migrations, control_property)
    credited: set[str] = set()
    results: list[LaunchTemplateMigrationResult] = []
    for target, launch_template_id, version in migrations:
        results.append(
            {
                "auto_scaling_group_name": target["auto_scaling_group_name"],
                "launch_template_id": launch_template_id,
                "version": version,
                "mode": target["mode"],
                "deleted_launch_configuration": _credit_deletion(
                    target, deleted_launch_configurations, credited
                ),
            }
        )
    return {
        "response": {
            "message": "Successfully migrated Auto Scaling group(s) to launch template",
            "status": "Success",
            "results": results,
        }
    }
