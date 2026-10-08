#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Locate the checkout of the ASR solution that the skill's scripts write into.

`generate_runbook.py` and `deploy_stack.py` share this lookup so they cannot drift
apart on where "the checkout" is: `ASR_WORKSPACE_ROOT` when set, otherwise the
nearest checkout at or above each of the caller's search starts. Anything else is
refused rather than written into.
"""
from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

# Files that identify a checkout of the solution. Both must be present: `deployment/`
# alone also exists in unrelated CDK projects.
CHECKOUT_MARKERS = ("deployment/upload-s3-dist.sh", "source/solution_deploy")


class CheckoutNotFoundError(Exception):
    """No checkout of the solution could be located; the message says why."""


def is_checkout(path: Path) -> bool:
    return all((path / marker).exists() for marker in CHECKOUT_MARKERS)


def resolve_checkout_root(search_starts: Sequence[Path]) -> Path:
    """Return the checkout root, or raise `CheckoutNotFoundError`.

    `ASR_WORKSPACE_ROOT` wins when set and must itself be a checkout. Otherwise each
    start is walked upward in order and the first checkout found is returned.
    """
    override = os.environ.get("ASR_WORKSPACE_ROOT")
    if override:
        candidate = Path(override).expanduser().resolve()
        if is_checkout(candidate):
            return candidate
        raise CheckoutNotFoundError(
            f"REFUSED: ASR_WORKSPACE_ROOT={override!r} is not a checkout of the "
            "solution (expected deployment/upload-s3-dist.sh and source/solution_deploy)."
        )
    for start in search_starts:
        resolved = start.resolve()
        for candidate in (resolved, *resolved.parents):
            if is_checkout(candidate):
                return candidate
    raise CheckoutNotFoundError(
        "REFUSED: no checkout of automated-security-response-on-aws found at or above "
        + " or ".join(str(start) for start in search_starts)
        + ". Run from inside the checkout, or set ASR_WORKSPACE_ROOT to it."
    )
