# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared pytest fixtures for the asr-remediation-authoring skill tests.

Puts the skill's ``scripts/`` directory on ``sys.path`` so tests can import the
tool modules directly (``import validate_runbook``) and exercise their pure
functions, in addition to invoking them as subprocesses for exit-code checks.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = SKILL_ROOT / "scripts"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Import tool modules by name (validate_runbook, generate_runbook, ...).
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin a region and dummy credentials for every test.

    Two reasons: (1) the tools resolve region from AWS_REGION and create their
    boto client in that region, so the test's moto store and the tool's store
    must agree; (2) dummy creds guarantee a moto miss can never reach real AWS.

    When ASR_SKILL_LIVE=1 is set, credentials are left untouched so that
    `test_live_integration.py` can reach real AWS with the caller's session.
    """
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    if os.environ.get("ASR_SKILL_LIVE") != "1":
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


@pytest.fixture()
def solution_checkout(tmp_path: Path) -> Path:
    """A directory carrying the marker files that identify a checkout of the solution."""
    root = tmp_path / "asr"
    (root / "deployment").mkdir(parents=True)
    (root / "deployment" / "upload-s3-dist.sh").write_text("#!/bin/sh\n")
    (root / "source" / "solution_deploy").mkdir(parents=True)
    return root.resolve()


@pytest.fixture(scope="session")
def scripts_dir() -> Path:
    return SCRIPTS_DIR


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture()
def valid_runbook_yaml() -> str:
    """A minimal runbook that passes strict validation (no verify/timeout gaps)."""
    return "\n".join(
        [
            'schemaVersion: "0.3"',
            "description: Minimal valid ASR runbook for tests.",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "parameters:",
            "  AutomationAssumeRole:",
            "    type: String",
            "    description: IAM role for automation execution",
            "  Finding:",
            "    type: StringMap",
            "    description: (Required) The ASFF finding, from the Orchestrator.",
            "mainSteps:",
            "  - name: VerifyResource",
            "    action: aws:assertAwsResourceProperty",
            "    inputs:",
            "      Service: s3",
            "      Api: GetBucketVersioning",
            '      PropertySelector: "$.Status"',
            "      DesiredValues:",
            "        - Enabled",
            "",
        ]
    )
