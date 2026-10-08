# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Validate the AWS account before scripts create or modify resources.

Callers fetch the STS identity through their selected AWS transport and pass it
here. Keeping the checks pure makes them reusable by CLI, SDK, and MCP-backed
workflows and keeps tests offline.
"""
from __future__ import annotations

import re

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")

# Account is the fifth colon-separated field of an ARN.
ARN_ACCOUNT_PATTERN = re.compile(r"^arn:[^:]*:[^:]*:[^:]*:(\d{12}):")

# Partition is the second. `aws`, `aws-us-gov`, `aws-cn` — and anything else AWS
# adds later, which is why this reads the value rather than matching a set.
ARN_PARTITION_PATTERN = re.compile(r"^arn:([a-z0-9-]+):")

# Scanned against the caller ARN as a second gate, after the account-ID match.
# "prod" also covers "production".
PRODUCTION_INDICATORS = ("prod", "prd")


def account_id_from_arn(arn: str) -> str:
    """Extract the account ID from an ARN, or return "" if there is not one.

    Used to recover the account a caller named indirectly, by passing a role ARN
    rather than an account ID.
    """
    match = ARN_ACCOUNT_PATTERN.match(arn)
    return match.group(1) if match else ""


def partition_from_arn(arn: str) -> str:
    """Extract the partition from an ARN, or return "" if it has none."""
    match = ARN_PARTITION_PATTERN.match(arn)
    return match.group(1) if match else ""


def check_identity(identity: object, expected_account_id: str) -> tuple[bool, str]:
    """Decide whether an `sts get-caller-identity` result may be acted on.

    Fails closed. The absence of a production marker is not evidence that an
    account is safe, so the load-bearing check is an equality test: the caller
    names an account, and credentials resolving to any other account are refused.
    Without it, whichever account the ambient `AWS_PROFILE` happens to point at
    receives the resources.

    The ARN marker scan stays as a second gate, for the case where the account
    the caller named is itself production.

    Returns `(ok, message)`; on refusal the message says which check failed.
    """
    if not ACCOUNT_ID_PATTERN.match(expected_account_id):
        return False, (
            f"expected a 12-digit account ID, got {expected_account_id!r} — cannot "
            "confirm which account these credentials should belong to"
        )
    if not isinstance(identity, dict):
        return False, "sts get-caller-identity did not return a JSON object"

    arn = str(identity.get("Arn", ""))
    account = str(identity.get("Account", ""))
    if not account:
        return False, "sts get-caller-identity returned no account ID"
    if account != expected_account_id:
        return False, (
            f"credentials are for account {account}, but {expected_account_id} was "
            "named — refusing to act on an account nobody asked for"
        )

    arn_lower = arn.lower()
    for indicator in PRODUCTION_INDICATORS:
        if indicator in arn_lower:
            return (
                False,
                f"Account looks like production (ARN contains '{indicator}'): {arn}",
            )

    return True, f"Account {account}, ARN: {arn}"
