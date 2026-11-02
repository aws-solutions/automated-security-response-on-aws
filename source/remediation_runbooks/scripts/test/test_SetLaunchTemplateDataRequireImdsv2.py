# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
from typing import Any

from ApplyLaunchTemplateToAutoScalingGroup import (
    normalize_security_group_placement,
)
from ResolveAutoScalingGroupLaunchSource import (
    launch_configuration_to_launch_template_data,
)
from SetLaunchTemplateDataRequireImdsv2 import (
    set_launch_template_data_require_imdsv2,
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


def test_sets_imdsv2_and_preserves_other_fields() -> None:
    context = _context(
        {
            "ImageId": "ami-1",
            "MetadataOptions": {"HttpPutResponseHopLimit": 3},
            "KeyName": "my-key",
        }
    )

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)

    launch_template_data = result["targets"][0]["launch_template_data"]
    assert launch_template_data["MetadataOptions"]["HttpTokens"] == "required"
    assert launch_template_data["MetadataOptions"]["HttpEndpoint"] == "enabled"
    # Existing hop limit and unrelated fields are preserved.
    assert launch_template_data["MetadataOptions"]["HttpPutResponseHopLimit"] == 3
    assert launch_template_data["KeyName"] == "my-key"


def test_disabled_endpoint_is_kept_disabled() -> None:
    # A source whose metadata endpoint is disabled keeps it disabled: the remediation
    # deletes the launch configuration and the new launch template falls under EC2.170,
    # which only requires HttpTokens=required and does not require the endpoint enabled.
    # Forcing it enabled would turn the metadata service back on for instances these
    # groups launch, so the endpoint is preserved (merge, not replace) while HttpTokens
    # is set to required and HttpPutResponseHopLimit is left untouched. The real EC2
    # CreateLaunchTemplate / RunInstances path accepts required together with a disabled
    # endpoint (verified against the live API).
    context = _context(
        {
            "ImageId": "ami-1",
            "MetadataOptions": {
                "HttpEndpoint": "disabled",
                "HttpPutResponseHopLimit": 1,
            },
        }
    )

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)

    metadata_options = result["targets"][0]["launch_template_data"]["MetadataOptions"]
    assert metadata_options["HttpTokens"] == "required"
    assert metadata_options["HttpEndpoint"] == "disabled"
    assert metadata_options["HttpPutResponseHopLimit"] == 1


def test_missing_endpoint_defaults_to_enabled_required() -> None:
    # A source with no HttpEndpoint defaults the endpoint to enabled (setdefault) while
    # setting HttpTokens=required and preserving the hop limit.
    context = _context(
        {
            "ImageId": "ami-1",
            "MetadataOptions": {"HttpPutResponseHopLimit": 2},
        }
    )

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)

    metadata_options = result["targets"][0]["launch_template_data"]["MetadataOptions"]
    assert metadata_options["HttpTokens"] == "required"
    assert metadata_options["HttpEndpoint"] == "enabled"
    assert metadata_options["HttpPutResponseHopLimit"] == 2


def test_userdata_round_trips_single_encoded_end_to_end() -> None:
    # UserData must stay single base64-encoded end to end, never double-encoded. On the
    # launch-template path botocore does NOT re-encode UserData for
    # ec2:CreateLaunchTemplate / CreateLaunchTemplateVersion, and the describe APIs
    # already return it base64-encoded, so it must be carried through exactly once. A
    # decode MUST NOT be reintroduced here: it would send raw text to
    # create_launch_template, which EC2 rejects as malformed base64.
    plaintext = "#!/bin/bash\necho hello\n"
    encoded_once = base64.b64encode(plaintext.encode()).decode()
    launch_configuration = {
        "ImageId": "ami-1",
        "InstanceType": "t3.micro",
        "UserData": encoded_once,
    }
    launch_template_data = launch_configuration_to_launch_template_data(
        launch_configuration
    )
    context = _context(launch_template_data)

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)

    fixed = result["targets"][0]["launch_template_data"]
    # Single-encoded value survives verbatim (no second encode, no decode).
    assert fixed["UserData"] == encoded_once
    # And it still decodes back to the original plaintext (not double-encoded).
    assert base64.b64decode(fixed["UserData"]).decode() == plaintext


def test_imdsv2_merge_preserves_disabled_endpoint_and_customer_fields_end_to_end() -> (
    None
):
    # MetadataOptions must not be clobbered (for example dropping
    # HttpPutResponseHopLimit). On the launch-template path the resolve step copies
    # the full MetadataOptions dict and the IMDSv2 step MERGES only HttpTokens while
    # preserving HttpEndpoint, so customer fields survive the full resolve -> IMDSv2
    # path end to end. The source here has the metadata endpoint disabled: the merge
    # must set HttpTokens=required and KEEP HttpEndpoint=disabled (it must NOT force
    # the endpoint back to enabled), while leaving HttpPutResponseHopLimit and
    # InstanceMetadataTags untouched. This end-to-end guard fails if forced-enabled
    # is ever reintroduced on the launch-template path.
    launch_configuration = {
        "ImageId": "ami-1",
        "InstanceType": "t3.micro",
        "MetadataOptions": {
            "HttpTokens": "optional",
            "HttpEndpoint": "disabled",
            "HttpPutResponseHopLimit": 4,
            "InstanceMetadataTags": "enabled",
        },
    }
    launch_template_data = launch_configuration_to_launch_template_data(
        launch_configuration
    )
    context = _context(launch_template_data)

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)

    metadata_options = result["targets"][0]["launch_template_data"]["MetadataOptions"]
    # IMDSv2 token requirement is enforced.
    assert metadata_options["HttpTokens"] == "required"
    # The disabled endpoint is preserved (merge, not replace): forcing it back to
    # enabled would turn the metadata service on for instances these groups launch.
    assert metadata_options["HttpEndpoint"] == "disabled"
    # Pre-existing customer fields are preserved end to end.
    assert metadata_options["HttpPutResponseHopLimit"] == 4
    assert metadata_options["InstanceMetadataTags"] == "enabled"


def test_no_action_needed_context_is_a_no_op() -> None:
    context = {"status": "NoActionNeeded", "targets": []}

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)

    assert result["targets"] == []


def test_autoscaling3_full_path_never_sets_groups_in_both_places() -> None:
    # Mandatory mutual-exclusion test (design Section 13): an LC that carries a
    # top-level SecurityGroups AND AssociatePublicIpAddress must, after the full
    # AutoScaling.3 path (convert -> IMDSv2 fix -> normalize), end up with the
    # groups on the device-0 NIC and no top-level SecurityGroupIds.
    launch_configuration = {
        "ImageId": "ami-1",
        "InstanceType": "t3.micro",
        "SecurityGroups": ["sg-aaa", "sg-bbb"],
        "AssociatePublicIpAddress": True,
    }
    launch_template_data = launch_configuration_to_launch_template_data(
        launch_configuration
    )
    context = _context(launch_template_data)

    result = set_launch_template_data_require_imdsv2({"Context": context}, None)
    fixed = result["targets"][0]["launch_template_data"]
    normalize_security_group_placement(fixed)

    assert "SecurityGroupIds" not in fixed
    assert fixed["NetworkInterfaces"][0]["Groups"] == ["sg-aaa", "sg-bbb"]
    assert fixed["MetadataOptions"]["HttpTokens"] == "required"
