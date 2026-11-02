# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
from typing import TYPE_CHECKING, Any, TypedDict, cast

if TYPE_CHECKING:
    from ResolveAutoScalingGroupLaunchSource import ResolveResult

# Import for tests/IDE; the build strips this fence and inlines the module below. Do not remove.
# fmt: off
from common.launch_template_property import (  # noqa: E402
    NO_PUBLIC_IP,
    apply_launch_template_property,
)
# fmt: on
# %%INCLUDE=common/launch_template_property.py%%


class BuildEvent(TypedDict):
    Context: ResolveResult


def _validate_build_event(event: dict[str, object]) -> BuildEvent:
    context = event.get("Context")
    if not isinstance(context, dict):
        raise ValueError(
            "Missing or invalid required parameter: Context "
            "(expected the resolve step output object)"
        )
    return BuildEvent(Context=cast("ResolveResult", context))


def set_launch_template_data_disable_public_ip(
    event: dict[str, object], _: Any
) -> ResolveResult:
    # Delegate to the shared launch_template_property module (single source of truth), the same
    # applier the Apply step and its fail-closed verify gate use, so this pre-pass cannot diverge.
    context = _validate_build_event(event)["Context"]
    for target in context.get("targets", []):
        apply_launch_template_property(target["launch_template_data"], NO_PUBLIC_IP)
    return context
