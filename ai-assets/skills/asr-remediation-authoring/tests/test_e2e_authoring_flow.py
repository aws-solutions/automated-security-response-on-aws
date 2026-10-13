# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/e2e_authoring_flow.py.

Most of this script is two thin AWS caller classes and a stage sequence, which the
opt-in live tier covers. What is worth testing without AWS is the pre-flight gate
in front of them, because this run creates an IAM role, an SSM document, and an
automation execution — so a wrong answer there puts real resources in the wrong
account.

`--mode cli` routes every call through the `aws` binary, which makes the stub-on-
PATH technique from `test_deploy_stack.py` work here too: the subprocess boundary
runs for real and nothing reaches AWS. The stub logs the calls it receives, so a
test can tell "refused" apart from "refused after asking AWS".
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Protocol

import e2e_authoring_flow
import pytest

DEV_ACCOUNT = "111111111111"
OTHER_ACCOUNT = "999999999999"
DEV_ROLE_ARN = f"arn:aws:iam::{DEV_ACCOUNT}:role/SO0111-Remediate-SC-2.0.0-E2ETest.1"

_AWS_STUB = '''#!/usr/bin/env python3
"""Stand-in for the `aws` CLI: logs the call, answers sts, exits 0 otherwise."""
import sys

argv = sys.argv[1:]
with open({calls!r}, "a", encoding="utf-8") as log:
    log.write(" ".join(argv[:2]) + "\\n")
if argv[:2] == ["sts", "get-caller-identity"]:
    sys.stdout.write({stdout!r})
sys.exit(0)
'''


class FakeAws(Protocol):
    """Installs the stub `aws` for one test, with the identity it should report."""

    def __call__(self, *, account: str = ..., arn: str = ...) -> None: ...


@pytest.fixture()
def aws_calls(tmp_path: Path) -> Path:
    """Where the stub records the calls it received."""
    return tmp_path / "aws-calls.log"


@pytest.fixture()
def fake_aws(
    tmp_path: Path, aws_calls: Path, monkeypatch: pytest.MonkeyPatch
) -> FakeAws:
    def install(*, account: str = DEV_ACCOUNT, arn: str = "") -> None:
        identity = {
            "Account": account,
            "Arn": arn or f"arn:aws:sts::{account}:assumed-role/authoring/session",
            "UserId": "AIDAEXAMPLE",
        }
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / "aws"
        script.write_text(
            _AWS_STUB.format(calls=str(aws_calls), stdout=json.dumps(identity)),
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    return install


def _run(assume_role: str = DEV_ROLE_ARN) -> list[e2e_authoring_flow.StageResult]:
    runner = e2e_authoring_flow.AuthoringFlowRunner(
        assume_role, region="us-east-1", mode="cli"
    )
    results = runner.run_all()
    # Teardown owns the temp workspace, so its removal is the evidence that
    # teardown ran even though the flow was cut short.
    assert not runner.workspace.exists(), "teardown skipped: workspace left behind"
    return results


def _stages(results: list[e2e_authoring_flow.StageResult]) -> list[str]:
    return [r["stage"] for r in results]


def test_refuses_credentials_for_an_account_the_assume_role_does_not_name(
    fake_aws: FakeAws,
) -> None:
    # The run creates an IAM role and an SSM document, so credentials pointing
    # somewhere other than the named account must stop before any of that.
    fake_aws(account=OTHER_ACCOUNT)

    results = _run()

    assert "preflight:identity" in _stages(results)
    assert "read" not in _stages(results)
    assert all(r["status"] != "PASS" or r["stage"] == "teardown" for r in results)


def test_refuses_a_production_looking_arn(fake_aws: FakeAws) -> None:
    # The account ID matches, but the production marker is a second stop gate.
    # The refusal must remain visible in the returned stage results.
    fake_aws(arn=f"arn:aws:iam::{DEV_ACCOUNT}:role/prod-deployer")

    results = _run()

    assert results, "refusal produced no result rows to report"
    refusal = next(r for r in results if r["stage"] == "preflight:identity")
    assert refusal["status"] == "FAIL"
    assert "production" in str(refusal["detail"])


def test_refuses_an_assume_role_arn_with_no_account(
    fake_aws: FakeAws, aws_calls: Path
) -> None:
    # Without an account in the ARN there is nothing to check credentials
    # against, so this refuses instead of falling through to a marker scan.
    fake_aws()

    results = _run(assume_role="arn:aws:iam::not-an-account:role/dev")

    assert "preflight:identity" in _stages(results)
    assert not aws_calls.exists(), "asked AWS before deciding it could not proceed"


def test_a_refusal_reports_a_nonzero_exit(fake_aws: FakeAws) -> None:
    # `main` derives its exit code from the result rows, so a refusal that was
    # recorded but not counted would exit 0 and read as a pass.
    fake_aws(account=OTHER_ACCOUNT)

    results = _run()

    assert any(r["status"] == "FAIL" for r in results)


@pytest.mark.parametrize(
    ("live", "assume_role"),
    [
        pytest.param(None, DEV_ROLE_ARN, id="live-flag-unset"),
        pytest.param("1", "", id="assume-role-unset"),
    ],
)
def test_main_will_not_start_without_its_required_environment(
    monkeypatch: pytest.MonkeyPatch, live: str | None, assume_role: str
) -> None:
    # This script only ever runs against a real account, so an accidental bare
    # invocation must refuse rather than pick defaults.
    monkeypatch.setattr("sys.argv", ["e2e_authoring_flow.py"])
    if live is None:
        monkeypatch.delenv("ASR_SKILL_LIVE", raising=False)
    else:
        monkeypatch.setenv("ASR_SKILL_LIVE", live)
    if assume_role:
        monkeypatch.setenv("ASR_TEST_ASSUME_ROLE", assume_role)
    else:
        monkeypatch.delenv("ASR_TEST_ASSUME_ROLE", raising=False)

    assert e2e_authoring_flow.main() == 1


def test_fill_steps_produces_a_runbook_that_passes_strict_validation() -> None:
    """The filled runbook must satisfy the Orchestrator parameter contract.

    The Orchestrator supplies `Finding` and `AutomationAssumeRole`. This test runs
    the real scaffold, fill, and strict-validation stages without contacting AWS.
    """
    import shutil

    runner = e2e_authoring_flow.AuthoringFlowRunner(
        DEV_ROLE_ARN, region="us-east-1", mode="cli"
    )
    try:
        runner._create()
        runner._fill_steps()
        runner._validate_complete()
    finally:
        shutil.rmtree(runner.workspace, ignore_errors=True)

    complete = next(r for r in runner.results if r["stage"] == "validate:complete")
    assert complete["status"] == "PASS", complete["detail"]


def test_start_automation_sends_the_required_finding_parameter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both caller paths must send Finding, or EXECUTE is rejected outright.

    The runbook declares Finding as required with no default, so an execution
    carrying only AutomationAssumeRole fails with
    InvalidAutomationExecutionParametersException. The boto3 and CLI callers each
    have to include it.
    """
    role_arn = f"arn:aws:iam::{DEV_ACCOUNT}:role/{e2e_authoring_flow.ROLE_NAME}"

    boto_caller = e2e_authoring_flow.BotoAwsCaller("us-east-1")
    captured: dict[str, Any] = {}

    class FakeSsm:
        def start_automation_execution(self, **kwargs: Any) -> dict[str, str]:
            captured.update(kwargs)
            return {"AutomationExecutionId": "exec-boto"}

    boto_caller.ssm = FakeSsm()
    boto_caller.start_automation(e2e_authoring_flow.DOC_NAME, role_arn)
    assert "Finding" in captured["Parameters"]

    cli_caller = e2e_authoring_flow.CliAwsCaller("us-east-1")
    cli_params: dict[str, Any] = {}

    def fake_run(cmd: list[str]) -> dict[str, str]:
        cli_params.update(json.loads(cmd[cmd.index("--parameters") + 1]))
        return {"AutomationExecutionId": "exec-cli"}

    monkeypatch.setattr(cli_caller, "_run", fake_run)
    cli_caller.start_automation(e2e_authoring_flow.DOC_NAME, role_arn)
    assert "Finding" in cli_params
