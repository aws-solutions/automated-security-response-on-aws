# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any

from ApplyLaunchTemplateToAutoScalingGroup import (
    normalize_security_group_placement,
)
from SetLaunchTemplateDataDisablePublicIp import (
    set_launch_template_data_disable_public_ip,
)


def _context(launch_template_data: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "ActionNeeded",
        "targets": [
            {
                "auto_scaling_group_name": "asg",
                "mode": "LaunchTemplate",
                "launch_template_data": launch_template_data,
            }
        ],
    }


def apply_disable_public_ip(launch_template_data: dict[str, Any]) -> dict[str, Any]:
    result = set_launch_template_data_disable_public_ip(
        {"Context": _context(launch_template_data)}, None
    )
    return result["targets"][0]["launch_template_data"]


def test_creates_device_zero_interface_when_none_present() -> None:
    fixed = apply_disable_public_ip({"ImageId": "ami-1"})

    assert fixed["NetworkInterfaces"] == [
        {"DeviceIndex": 0, "AssociatePublicIpAddress": False}
    ]


def test_reuses_primary_nic_missing_device_index_without_duplicating() -> None:
    # Mandatory device-0 dedup test (design Section 13 / Finding 1): a single NIC
    # that omits DeviceIndex must be reused in place, not duplicated.
    fixed = apply_disable_public_ip(
        {
            "NetworkInterfaces": [
                {"AssociatePublicIpAddress": True, "Groups": ["sg-1"]}
            ]
        }
    )

    assert len(fixed["NetworkInterfaces"]) == 1
    assert fixed["NetworkInterfaces"][0]["DeviceIndex"] == 0
    assert fixed["NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False
    # Unrelated fields preserved.
    assert fixed["NetworkInterfaces"][0]["Groups"] == ["sg-1"]


def test_disables_public_ip_on_all_interfaces() -> None:
    # Mandatory multi-NIC test (design Section 13 / Finding 4).
    fixed = apply_disable_public_ip(
        {
            "NetworkInterfaces": [
                {"DeviceIndex": 0, "AssociatePublicIpAddress": True},
                {"DeviceIndex": 1, "AssociatePublicIpAddress": True},
            ]
        }
    )

    assert all(
        interface["AssociatePublicIpAddress"] is False
        for interface in fixed["NetworkInterfaces"]
    )


def test_autoscaling5_full_path_relocates_security_groups() -> None:
    # The fix forces a device-0 NIC; normalize must then move the top-level groups
    # onto it so EC2 never receives both.
    launch_template_data = {
        "ImageId": "ami-1",
        "SecurityGroupIds": ["sg-aaa", "sg-bbb"],
    }
    fixed = apply_disable_public_ip(launch_template_data)
    normalize_security_group_placement(fixed)

    assert "SecurityGroupIds" not in fixed
    assert fixed["NetworkInterfaces"][0]["Groups"] == ["sg-aaa", "sg-bbb"]
    assert fixed["NetworkInterfaces"][0]["AssociatePublicIpAddress"] is False
