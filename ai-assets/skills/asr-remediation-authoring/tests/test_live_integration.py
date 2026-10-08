# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Live AWS integration for the test/deploy tools — the only non-hermetic tests.

These tests touch a REAL AWS account, so they are OPT-IN and gated behind an
environment variable to guarantee they never run in the offline pipeline or,
per the production-safety rule, against anything but an explicitly-provided dev
account.

Enable with:
    ASR_SKILL_LIVE=1 ASR_TEST_ASSUME_ROLE=arn:aws:iam::<dev-acct>:role/<remediation-role> \
      AWS_REGION=us-east-1 python3 -m pytest tests/test_live_integration.py -v

The headline assertion mirrors the unit test but for real: after a live
execution, the transient SSM document must be gone from the account.
"""
from __future__ import annotations

import os
import types

import pytest

LIVE = os.environ.get("ASR_SKILL_LIVE") == "1"
pytestmark = pytest.mark.skipif(
    not LIVE, reason="set ASR_SKILL_LIVE=1 to run live AWS integration"
)


@pytest.fixture()
def assume_role() -> str:
    role = os.environ.get("ASR_TEST_ASSUME_ROLE")
    if not role:
        pytest.skip("ASR_TEST_ASSUME_ROLE not set")
    return role


def test_live_test_runbook_executes_and_cleans_up(assume_role: str) -> None:
    import boto3
    import test_runbook

    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    assert region
    args = types.SimpleNamespace(
        script="live",
        script_body=(
            "import boto3\n\n"
            "def handler(event, context):\n"
            f"    identity = boto3.client('sts', region_name={region!r})"
            ".get_caller_identity()\n"
            "    return {'account': identity['Account'], 'arn': identity['Arn']}\n"
        ),
        handler="handler",
        runtime="python3.11",
        input_payload=None,
        timeout=180,
        assume_role=assume_role,
        control_id="LIVE.1",
        document_name=None,
        cleanup=True,
    )
    result = test_runbook.run(args)

    # The API call must succeed under the supplied role. A constant-return
    # handler would not detect missing credentials inside executeScript.
    assert result["status"] == "Success", f"credential probe failed: {result}"
    output = result["output"]
    expected_account = assume_role.split(":")[4]
    expected_role_name = assume_role.rsplit("/", maxsplit=1)[-1]
    assert output["account"] == expected_account
    assert f"assumed-role/{expected_role_name}/" in output["arn"]

    # Whatever the execution outcome, the cleanup guarantee must hold for real.
    assert result["cleanedUp"] is True, f"transient document not cleaned up: {result}"

    ssm = boto3.client("ssm", region_name=region)
    with pytest.raises(ssm.exceptions.InvalidDocument):
        ssm.get_document(Name=result["documentName"])
