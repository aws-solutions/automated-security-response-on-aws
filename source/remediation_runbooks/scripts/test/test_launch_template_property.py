# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any

import pytest
from common.launch_template_property import (
    NO_PUBLIC_IP,
    REQUIRE_IMDSV2,
    apply_launch_template_property,
    verify_launch_template_property,
)


def test_apply_require_imdsv2_sets_required_and_preserves_hop_limit() -> None:
    launch_template_data: dict[str, Any] = {
        "ImageId": "ami-1",
        "MetadataOptions": {"HttpPutResponseHopLimit": 3},
    }

    apply_launch_template_property(launch_template_data, REQUIRE_IMDSV2)

    metadata_options = launch_template_data["MetadataOptions"]
    assert metadata_options["HttpTokens"] == "required"
    assert metadata_options["HttpEndpoint"] == "enabled"
    assert metadata_options["HttpPutResponseHopLimit"] == 3


def test_apply_require_imdsv2_keeps_disabled_endpoint_disabled() -> None:
    launch_template_data: dict[str, Any] = {
        "MetadataOptions": {"HttpEndpoint": "disabled", "HttpPutResponseHopLimit": 1}
    }

    apply_launch_template_property(launch_template_data, REQUIRE_IMDSV2)

    metadata_options = launch_template_data["MetadataOptions"]
    assert metadata_options["HttpTokens"] == "required"
    assert metadata_options["HttpEndpoint"] == "disabled"
    assert metadata_options["HttpPutResponseHopLimit"] == 1


def test_apply_require_imdsv2_defaults_absent_endpoint_to_enabled() -> None:
    launch_template_data: dict[str, Any] = {"ImageId": "ami-1"}

    apply_launch_template_property(launch_template_data, REQUIRE_IMDSV2)

    metadata_options = launch_template_data["MetadataOptions"]
    assert metadata_options["HttpTokens"] == "required"
    assert metadata_options["HttpEndpoint"] == "enabled"


def test_apply_no_public_ip_disables_every_interface() -> None:
    launch_template_data: dict[str, Any] = {
        "NetworkInterfaces": [
            {"DeviceIndex": 0, "AssociatePublicIpAddress": True},
            {"DeviceIndex": 1, "AssociatePublicIpAddress": True},
        ]
    }

    apply_launch_template_property(launch_template_data, NO_PUBLIC_IP)

    assert all(
        interface["AssociatePublicIpAddress"] is False
        for interface in launch_template_data["NetworkInterfaces"]
    )


def test_apply_no_public_ip_synthesizes_device_zero_when_none_exist() -> None:
    launch_template_data: dict[str, Any] = {"ImageId": "ami-1"}

    apply_launch_template_property(launch_template_data, NO_PUBLIC_IP)

    assert launch_template_data["NetworkInterfaces"] == [
        {"DeviceIndex": 0, "AssociatePublicIpAddress": False}
    ]


def test_apply_is_idempotent_for_both_properties() -> None:
    imdsv2_data: dict[str, Any] = {"MetadataOptions": {"HttpPutResponseHopLimit": 2}}
    apply_launch_template_property(imdsv2_data, REQUIRE_IMDSV2)
    once = {"MetadataOptions": dict(imdsv2_data["MetadataOptions"])}
    apply_launch_template_property(imdsv2_data, REQUIRE_IMDSV2)
    assert imdsv2_data["MetadataOptions"] == once["MetadataOptions"]

    no_public_ip_data: dict[str, Any] = {"ImageId": "ami-1"}
    apply_launch_template_property(no_public_ip_data, NO_PUBLIC_IP)
    once_interfaces = [dict(nic) for nic in no_public_ip_data["NetworkInterfaces"]]
    apply_launch_template_property(no_public_ip_data, NO_PUBLIC_IP)
    assert no_public_ip_data["NetworkInterfaces"] == once_interfaces


def test_verify_positive_cases_return_true() -> None:
    assert (
        verify_launch_template_property(
            {"MetadataOptions": {"HttpTokens": "required"}}, REQUIRE_IMDSV2
        )
        is True
    )
    assert (
        verify_launch_template_property(
            {
                "NetworkInterfaces": [
                    {"DeviceIndex": 0, "AssociatePublicIpAddress": False},
                    {"DeviceIndex": 1, "AssociatePublicIpAddress": False},
                ]
            },
            NO_PUBLIC_IP,
        )
        is True
    )


def test_verify_require_imdsv2_optional_is_false() -> None:
    assert (
        verify_launch_template_property(
            {"MetadataOptions": {"HttpTokens": "optional"}}, REQUIRE_IMDSV2
        )
        is False
    )


def test_verify_require_imdsv2_without_metadata_options_is_false() -> None:
    assert verify_launch_template_property({"ImageId": "ami-1"}, REQUIRE_IMDSV2) is False


def test_verify_no_public_ip_one_interface_public_is_false() -> None:
    assert (
        verify_launch_template_property(
            {
                "NetworkInterfaces": [
                    {"DeviceIndex": 0, "AssociatePublicIpAddress": False},
                    {"DeviceIndex": 1, "AssociatePublicIpAddress": True},
                ]
            },
            NO_PUBLIC_IP,
        )
        is False
    )


def test_verify_no_public_ip_absent_interfaces_is_false() -> None:
    assert verify_launch_template_property({"ImageId": "ami-1"}, NO_PUBLIC_IP) is False


def test_verify_no_public_ip_empty_interfaces_is_false() -> None:
    assert (
        verify_launch_template_property({"NetworkInterfaces": []}, NO_PUBLIC_IP) is False
    )


def test_unknown_property_id_raises_for_apply_and_verify() -> None:
    with pytest.raises(ValueError, match="unknown-property"):
        apply_launch_template_property({}, "unknown-property")
    with pytest.raises(ValueError, match="unknown-property"):
        verify_launch_template_property({}, "unknown-property")
