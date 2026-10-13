# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/account_guard.py.

This is the gate in front of every resource-creating script in the skill, and it
is pure, so it is tested directly rather than through either caller. What matters
is that it fails closed: only an exact account match returns True, and everything
ambiguous — a missing account, a non-object identity, a malformed expectation —
refuses.
"""
from __future__ import annotations

from typing import Any

import account_guard
import pytest

DEV_ACCOUNT = "111111111111"
OTHER_ACCOUNT = "999999999999"


def _identity(account: str = DEV_ACCOUNT, arn: str = "") -> dict[str, str]:
    return {"Account": account, "Arn": arn or f"arn:aws:iam::{account}:role/dev"}


def test_matching_account_is_allowed() -> None:
    is_safe, message = account_guard.check_identity(_identity(), DEV_ACCOUNT)

    assert is_safe
    assert DEV_ACCOUNT in message


def test_a_different_account_is_refused() -> None:
    # The check that matters: holding credentials for an account nobody named
    # must stop, whatever the ARN happens to look like.
    is_safe, message = account_guard.check_identity(
        _identity(OTHER_ACCOUNT), DEV_ACCOUNT
    )

    assert not is_safe
    assert OTHER_ACCOUNT in message and DEV_ACCOUNT in message


def test_an_admin_role_in_an_unnamed_account_is_refused() -> None:
    # The case the old marker-only scan let through: no "prod" anywhere, so it
    # was treated as safe and the script went on to create resources.
    is_safe, _ = account_guard.check_identity(
        _identity(OTHER_ACCOUNT, f"arn:aws:iam::{OTHER_ACCOUNT}:role/Admin"),
        DEV_ACCOUNT,
    )

    assert not is_safe


@pytest.mark.parametrize("marker", ["prod", "production", "prd", "PROD", "Prod"])
def test_a_production_marker_is_refused_even_when_the_account_matches(
    marker: str,
) -> None:
    # Second gate, for when the account the caller named is itself production.
    is_safe, message = account_guard.check_identity(
        _identity(arn=f"arn:aws:iam::{DEV_ACCOUNT}:role/{marker}-deployer"),
        DEV_ACCOUNT,
    )

    assert not is_safe
    assert "production" in message


@pytest.mark.parametrize(
    "expected", ["", "12345", "1234567890123", "12345678901a", f"{DEV_ACCOUNT} "]
)
def test_a_malformed_expected_account_is_refused(expected: str) -> None:
    # With nothing well-formed to compare against there is no check to pass, so
    # this must refuse rather than fall through.
    is_safe, message = account_guard.check_identity(_identity(), expected)

    assert not is_safe
    assert "12-digit" in message


@pytest.mark.parametrize(
    "identity",
    [
        pytest.param(None, id="none"),
        pytest.param([], id="list"),
        pytest.param("arn:aws:iam::111111111111:role/dev", id="string"),
    ],
)
def test_an_identity_that_is_not_an_object_is_refused(identity: Any) -> None:
    is_safe, message = account_guard.check_identity(identity, DEV_ACCOUNT)

    assert not is_safe
    assert "JSON object" in message


def test_an_identity_without_an_account_is_refused() -> None:
    is_safe, message = account_guard.check_identity(
        {"Arn": "arn:aws:iam::x"}, DEV_ACCOUNT
    )

    assert not is_safe
    assert "no account ID" in message


@pytest.mark.parametrize(
    ("arn", "expected"),
    [
        pytest.param(
            f"arn:aws:iam::{DEV_ACCOUNT}:role/SO0111-Remediate-SC-2.0.0-EC2.60",
            DEV_ACCOUNT,
            id="iam-role",
        ),
        pytest.param(
            f"arn:aws:sts::{DEV_ACCOUNT}:assumed-role/authoring/session",
            DEV_ACCOUNT,
            id="assumed-role",
        ),
        pytest.param(
            f"arn:aws-us-gov:iam::{DEV_ACCOUNT}:role/dev",
            DEV_ACCOUNT,
            id="gov-partition",
        ),
        pytest.param("", "", id="empty"),
        pytest.param("not-an-arn", "", id="not-an-arn"),
        pytest.param("arn:aws:s3:::my-bucket", "", id="no-account-field"),
        pytest.param("arn:aws:iam::12345:role/dev", "", id="account-too-short"),
    ],
)
def test_account_id_is_read_out_of_an_arn(arn: str, expected: str) -> None:
    # `e2e_authoring_flow.py` names its account indirectly, through the
    # assume-role ARN, so a silent "" here would disable its whole guard.
    assert account_guard.account_id_from_arn(arn) == expected
