# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Single source of truth for applying and verifying each control's launch-template property.

Apply (write) and the Apply verify gate (read-after-write) both call this module, so apply and
verify can never disagree. Unknown property_id fails closed with ValueError.
"""
# This module is inlined verbatim into host scripts by the %%INCLUDE directive, so it must not
# declare `from __future__ import annotations`: the host scripts already declare it at their top,
# and a second occurrence mid-file is a SyntaxError. The annotations used here evaluate fine on
# python3.11 without the future import.
from typing import Any

REQUIRE_IMDSV2 = "require_imdsv2"
NO_PUBLIC_IP = "no_public_ip"


def _apply_require_imdsv2(launch_template_data: dict[str, Any]) -> None:
    # setdefault keeps a disabled HttpEndpoint disabled and defaults only an absent one to
    # enabled; the existing HttpPutResponseHopLimit is preserved.
    metadata_options = dict(launch_template_data.get("MetadataOptions") or {})
    metadata_options["HttpTokens"] = "required"
    metadata_options.setdefault("HttpEndpoint", "enabled")
    launch_template_data["MetadataOptions"] = metadata_options


def _apply_no_public_ip(launch_template_data: dict[str, Any]) -> None:
    # Disable public IP on every interface, synthesizing a DeviceIndex=0 interface if none exist.
    network_interfaces = launch_template_data.get("NetworkInterfaces", [])
    if network_interfaces:
        for network_interface in network_interfaces:
            network_interface["AssociatePublicIpAddress"] = False
        device0 = next(
            (
                interface
                for interface in network_interfaces
                if interface.get("DeviceIndex") == 0
            ),
            network_interfaces[0],
        )
        device0["DeviceIndex"] = 0
        device0["AssociatePublicIpAddress"] = False
    else:
        network_interfaces = [{"DeviceIndex": 0, "AssociatePublicIpAddress": False}]
    launch_template_data["NetworkInterfaces"] = network_interfaces


def apply_launch_template_property(
    launch_template_data: dict[str, Any], property_id: str
) -> None:
    # Mutate launch_template_data in place to satisfy the control. Idempotent.
    if property_id == REQUIRE_IMDSV2:
        _apply_require_imdsv2(launch_template_data)
        return
    if property_id == NO_PUBLIC_IP:
        _apply_no_public_ip(launch_template_data)
        return
    raise ValueError(f"Unknown launch template property: {property_id}")


def _verify_require_imdsv2(launch_template_data: dict[str, Any]) -> bool:
    return launch_template_data.get("MetadataOptions", {}).get("HttpTokens") == "required"


def _verify_no_public_ip(launch_template_data: dict[str, Any]) -> bool:
    # Fail closed: an absent or empty NetworkInterfaces list is never vacuously True, and every
    # interface must be False (identity check, so a truthy non-boolean cannot pass).
    network_interfaces = launch_template_data.get("NetworkInterfaces") or []
    return bool(network_interfaces) and all(
        interface.get("AssociatePublicIpAddress") is False
        for interface in network_interfaces
    )


def verify_launch_template_property(
    launch_template_data: dict[str, Any], property_id: str
) -> bool:
    # Mirror of apply_launch_template_property, used by the Apply fail-closed verify gate.
    if property_id == REQUIRE_IMDSV2:
        return _verify_require_imdsv2(launch_template_data)
    if property_id == NO_PUBLIC_IP:
        return _verify_no_public_ip(launch_template_data)
    raise ValueError(f"Unknown launch template property: {property_id}")
