# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/test_runbook.py.

The headline guarantee of this tool is: **the transient SSM document is deleted
on EVERY exit path** (success, failure, timeout, exception, Ctrl-C). That
guarantee is the reason the step is code and not prose, so it is the #1 thing
these tests prove.

Two boundary strategies, both per convention (simulate the service, don't fake
our own functions):
  * moto — used for the real document CRUD + the failure/cleanup path. moto does
    NOT implement start_automation_execution, so calling it raises inside run(),
    which is exactly the "exception exit still deletes" case we most want to
    prove with real service behavior.
  * FakeSsm — a minimal documented stand-in ONLY for the automation-execution
    calls moto cannot simulate (success + timeout orchestration). It records
    delete_document so we can assert cleanup there too.
"""
from __future__ import annotations

import types
from collections.abc import Callable
from pathlib import Path

import boto3
import pytest
import test_runbook
from botocore.exceptions import ClientError
from moto import mock_aws

REGION = "us-east-1"
# The role a caller would realistically pass: the remediation's own role, so the
# execution proves the permissions the deployed runbook will actually have.
ROLE = "arn:aws:iam::123456789012:role/SO0111-Remediate-SC-2.0.0-S3.9"
SCRIPT_BODY = "def handler(event, context):\n    return {'ok': True}\n"


def _args(**overrides: object) -> types.SimpleNamespace:
    base: dict[str, object] = dict(
        script="ignored",
        script_body=SCRIPT_BODY,
        handler="handler",
        runtime="python3.11",
        input_payload=None,
        timeout=5,
        assume_role=ROLE,
        control_id="S3.9",
        document_name=None,
        cleanup=True,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _failure_message(report: test_runbook.RunbookTestReport) -> str:
    """The report's failure message, asserted present before it is matched.

    `failureMessage` is `str | None` — a substring check against `None` is a
    `TypeError`, and reading "expected a failure message, got None" beats
    reading that.
    """
    message = report["failureMessage"]
    assert message is not None, "expected a failure message, got None"
    return message


# --- pure helpers ------------------------------------------------------------


def test_build_document_includes_role_param_and_script() -> None:
    doc = test_runbook.build_document(
        "python3.11", "handler", SCRIPT_BODY, ["BucketName"], 600
    )
    assert 'schemaVersion: "0.3"' in doc
    assert 'assumeRole: "{{ AutomationAssumeRole }}"' in doc
    assert "AutomationAssumeRole:" in doc
    assert "BucketName:" in doc
    assert "timeoutSeconds: 600" in doc
    assert "return {'ok': True}" in doc


def test_generate_document_name_slugs_the_control_or_honours_an_explicit_name() -> None:
    assert test_runbook.generate_document_name(None, "S3.9").startswith(
        "ASR-Custom-TestRemediation-S3-9-"
    )
    assert test_runbook.generate_document_name("MyName", "S3.9") == "MyName"


def test_extract_payload_walks_every_fallback() -> None:
    """Four places a payload can live, plus the two shapes that have none.

    One test rather than six because these are the branches of a single `or`
    chain over a dict — there is no setup to share and no state, so a table of
    inputs reads as the specification the chain implements. The JSON-vs-raw pairs
    matter most: a handler that prints instead of returning JSON must still be
    reported, not lost to a decode error.
    """
    step_payload = {
        "StepExecutions": [{"Outputs": {"Payload": ['{"result": "done"}']}}]
    }
    assert test_runbook.extract_payload(step_payload) == {"result": "done"}

    step_raw = {"StepExecutions": [{"Outputs": {"Payload": ["not json at all"]}}]}
    assert test_runbook.extract_payload(step_raw) == "not json at all"

    # No step-level Payload -> read the document-level output key.
    execution_payload = {
        "StepExecutions": [{}],
        "Outputs": {"RunCandidateScript.Payload": ['{"from": "outputs"}']},
    }
    assert test_runbook.extract_payload(execution_payload) == {"from": "outputs"}

    execution_raw = {
        "StepExecutions": [{}],
        "Outputs": {"RunCandidateScript.Payload": ["raw text"]},
    }
    assert test_runbook.extract_payload(execution_raw) == "raw text"

    assert test_runbook.extract_payload({}) is None
    assert test_runbook.extract_payload({"StepExecutions": [{}], "Outputs": {}}) is None


# --- %%INCLUDE expansion: a rollback handler is testable as-authored ----------

COMMON_MODULE_BODY = "def read_snapshot():\n    return 'snapshot'\n"
ROLLBACK_HANDLER_BODY = (
    "import json\n"
    "# fmt: off\n"
    "from common.snapshot_utils import (  # noqa: E402\n"
    "    read_snapshot,\n"
    ")\n"
    "# fmt: on\n"
    "# %%INCLUDE=common/snapshot_utils.py%%\n"
    "\n"
    "def handler(event, context):\n"
    "    return {'snapshot': read_snapshot()}\n"
)


def _common_dir(tmp_path: Path) -> Path:
    common_dir = tmp_path / "common"
    common_dir.mkdir()
    (common_dir / "snapshot_utils.py").write_text(COMMON_MODULE_BODY, encoding="utf-8")
    return common_dir


def test_include_inlines_the_common_module_and_strips_the_test_import(
    tmp_path: Path,
) -> None:
    """The build's contract: SSM has no `common` package, so the import must go and the
    module body must take its place — otherwise the handler dies on ModuleNotFoundError.
    """
    resolved = test_runbook.resolve_includes(
        ROLLBACK_HANDLER_BODY, tmp_path, _common_dir(tmp_path)
    )

    assert "from common" not in resolved
    assert "%%INCLUDE" not in resolved
    assert "def read_snapshot():" in resolved
    assert resolved.index("def read_snapshot():") < resolved.index("def handler(")
    compile(resolved, "handler.py", "exec")


def test_include_drops_only_one_trailing_newline_like_the_build(tmp_path: Path) -> None:
    """The build strips one trailing newline (`replace(/\\n$/, '')`), not all of them, so a
    module ending in a blank line keeps it and the test doc matches the built doc."""
    common_dir = tmp_path / "common"
    common_dir.mkdir()
    (common_dir / "snapshot_utils.py").write_text("X = 1\n\n", encoding="utf-8")

    resolved = test_runbook.resolve_includes(
        "# %%INCLUDE=common/snapshot_utils.py%%\nY = 2", tmp_path, common_dir
    )

    assert resolved == "X = 1\n\nY = 2"


def test_script_without_include_is_returned_unchanged(tmp_path: Path) -> None:
    assert test_runbook.resolve_includes(SCRIPT_BODY, tmp_path, None) == SCRIPT_BODY


def test_fmt_fence_that_is_not_the_common_import_is_kept(tmp_path: Path) -> None:
    """Only the `from common...` shim is stripped; an unrelated formatter fence above the
    directive is author code and must survive, as it does in the build."""
    script = (
        "# fmt: off\n"
        "TABLE = [1,   2,   3]\n"
        "# fmt: on\n"
        "# %%INCLUDE=common/snapshot_utils.py%%\n"
    )

    resolved = test_runbook.resolve_includes(script, tmp_path, _common_dir(tmp_path))

    assert "TABLE = [1,   2,   3]" in resolved
    assert "def read_snapshot():" in resolved


def test_main_exits_two_when_an_include_has_no_common_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rollback handler tested outside a checkout, without --common-dir, is refused
    before any AWS call rather than sent to SSM to fail on the import."""
    script = tmp_path / "handler_rollback.py"
    script.write_text(ROLLBACK_HANDLER_BODY, encoding="utf-8")

    argv = ["test_runbook.py", "--script", str(script), "--assume-role", ROLE]

    assert test_runbook.main(argv) == 2
    assert "--common-dir" in capsys.readouterr().err


# --- run(): a caller-provided role is required and none is ever created ------


def test_no_role_is_refused_before_any_aws_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing execution credentials must fail before creating an SSM document.

    The executeScript sandbox cannot sign SDK requests without an assume role.
    Refusing at the boundary prevents the confusing live failure and guarantees
    that no transient document needs cleanup.
    """
    monkeypatch.delenv("ASR_TEST_ASSUME_ROLE", raising=False)

    def fake_client(service: str, **kwargs: object) -> None:
        pytest.fail(f"unexpected AWS client built for {service}")

    monkeypatch.setattr(boto3, "client", fake_client)

    with pytest.raises(ValueError, match="aws:executeScript does not inherit"):
        test_runbook.run(_args(assume_role=None))


def test_env_var_supplies_the_role_when_the_flag_is_absent(
    monkeypatch: pytest.MonkeyPatch, patch_client: Callable[[FakeSsm], None]
) -> None:
    monkeypatch.setenv("ASR_TEST_ASSUME_ROLE", ROLE)
    recorded = {}

    class RecordingSsm(FakeSsm):
        def start_automation_execution(self, **kwargs: object) -> dict[str, str]:
            recorded.update(kwargs)
            return {"AutomationExecutionId": "exec-123"}

    patch_client(RecordingSsm("Success"))
    test_runbook.run(_args(assume_role=None))
    assert recorded["Parameters"] == {"AutomationAssumeRole": [ROLE]}


# --- THE GUARANTEE: cleanup on the failure/exception path (real moto) --------


@mock_aws
def test_document_deleted_even_when_execution_fails() -> None:
    # moto implements create/get/delete_document but NOT start_automation_execution,
    # so run() hits the except branch. The finally block must still delete the doc.
    result = test_runbook.run(_args())
    assert result["cleanedUp"] is True
    assert result["failureMessage"]  # a failure was recorded
    # Prove the document is really gone from the (simulated) account.
    ssm = boto3.client("ssm", region_name=REGION)
    with pytest.raises(ssm.exceptions.InvalidDocument):
        ssm.get_document(Name=result["documentName"])


@mock_aws
def test_no_cleanup_flag_leaves_document_behind() -> None:
    result = test_runbook.run(_args(cleanup=False))
    assert result["cleanedUp"] is False
    ssm = boto3.client("ssm", region_name=REGION)
    # Document still exists (no exception).
    doc = ssm.get_document(Name=result["documentName"])
    assert doc["Name"] == result["documentName"]


# --- success + timeout orchestration (FakeSsm boundary) ----------------------


class FakeSsm:
    """Minimal SSM stand-in for the automation calls moto cannot simulate.

    Records delete_document so cleanup can be asserted on the success path too.
    """

    class _Exc:
        class InvalidDocument(Exception):
            pass

    def __init__(self, terminal_status: str) -> None:
        self._status = terminal_status
        self.created = False
        self.deleted = False
        self.exceptions = FakeSsm._Exc()

    def create_document(self, **kwargs: object) -> dict[str, object]:
        self.created = True
        return {}

    def start_automation_execution(self, **kwargs: object) -> dict[str, str]:
        return {"AutomationExecutionId": "exec-123"}

    def get_automation_execution(self, **kwargs: object) -> dict[str, object]:
        return {
            "AutomationExecution": {
                "AutomationExecutionStatus": self._status,
                "FailureMessage": "" if self._status == "Success" else "boom",
                "StepExecutions": [{"Outputs": {"Payload": ['{"done": true}']}}],
            }
        }

    def delete_document(self, **kwargs: object) -> dict[str, object]:
        self.deleted = True
        return {}


@pytest.fixture()
def patch_client(monkeypatch: pytest.MonkeyPatch) -> Callable[[FakeSsm], None]:
    """Point run()'s boto3.client at a FakeSsm for automation-execution paths."""

    def _install(fake: FakeSsm) -> None:
        monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)

    return _install


def test_success_path_reports_success_and_cleans_up(
    patch_client: Callable[[FakeSsm], None]
) -> None:
    fake = FakeSsm("Success")
    patch_client(fake)
    result = test_runbook.run(_args())
    assert result["status"] == "Success"
    assert result["output"] == {"done": True}
    assert result["cleanedUp"] is True
    assert fake.deleted is True


def test_failed_execution_reports_failure_and_cleans_up(
    patch_client: Callable[[FakeSsm], None]
) -> None:
    fake = FakeSsm("Failed")
    patch_client(fake)
    result = test_runbook.run(_args())
    assert result["status"] == "Failed"
    assert result["failureMessage"] == "boom"
    assert result["cleanedUp"] is True
    assert fake.deleted is True


def test_timeout_still_cleans_up(patch_client: Callable[[FakeSsm], None]) -> None:
    # THE GUARANTEE on the timeout path: a negative timeout puts the deadline in
    # the past, so wait_for_terminal raises TimeoutError without ever sleeping.
    # The except branch records it and finally still deletes the document.
    fake = FakeSsm("InProgress")  # never terminal
    patch_client(fake)
    result = test_runbook.run(_args(timeout=-30))
    assert result["status"] is None
    assert "did not reach a terminal state" in _failure_message(result)
    assert result["cleanedUp"] is True
    assert fake.deleted is True


def test_missing_execution_id_is_reported_and_cleans_up(
    patch_client: Callable[[FakeSsm], None]
) -> None:
    class NoIdSsm(FakeSsm):
        def start_automation_execution(self, **kwargs: object) -> dict[str, str]:
            return {}

    fake = NoIdSsm("Success")
    patch_client(fake)
    result = test_runbook.run(_args())
    assert "no AutomationExecutionId" in _failure_message(result)
    assert result["cleanedUp"] is True
    assert fake.deleted is True


def test_delete_failure_is_reported_not_raised(
    patch_client: Callable[[FakeSsm], None]
) -> None:
    # If cleanup itself fails, the report must name the problem so the caller
    # knows a document was left behind — a raise here would lose the result.
    class UndeletableSsm(FakeSsm):
        def delete_document(self, **kwargs: object) -> dict[str, object]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DeleteDocument"
            )

    patch_client(UndeletableSsm("Success"))
    result = test_runbook.run(_args())
    assert result["cleanedUp"] is False
    assert "AccessDenied" in _failure_message(result)


def test_input_payload_values_are_stringified(
    patch_client: Callable[[FakeSsm], None]
) -> None:
    # SSM parameters are lists of strings, so a non-string input must be encoded.
    recorded = {}

    class RecordingSsm(FakeSsm):
        def start_automation_execution(self, **kwargs: object) -> dict[str, str]:
            recorded.update(kwargs)
            return {"AutomationExecutionId": "exec-123"}

    patch_client(RecordingSsm("Success"))
    test_runbook.run(_args(input_payload='{"BucketName": "b", "Count": 3}'))
    assert recorded["Parameters"] == {
        "AutomationAssumeRole": [ROLE],
        "BucketName": ["b"],
        "Count": ["3"],
    }


# --- main(): the CLI exit-code contract --------------------------------------
# Called in-process rather than via subprocess so the assertions cover the real
# main() branches (a subprocess would only prove the exit code).


def _script_file(tmp_path: Path) -> str:
    f = tmp_path / "handler.py"
    f.write_text(SCRIPT_BODY, encoding="utf-8")
    return str(f)


def test_main_exit_zero_on_success(
    patch_client: Callable[[FakeSsm], None], tmp_path: Path
) -> None:
    patch_client(FakeSsm("Success"))
    argv = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
    ]
    assert test_runbook.main(argv) == 0


def test_main_exit_one_on_non_success(
    patch_client: Callable[[FakeSsm], None], tmp_path: Path
) -> None:
    patch_client(FakeSsm("Failed"))
    argv = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
    ]
    assert test_runbook.main(argv) == 1


def test_main_exit_one_when_a_requested_cleanup_failed(
    patch_client: Callable[[FakeSsm], None],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A succeeded execution whose document could not be deleted is not a clean run:
    # SSM has no TTL, so the transient document is now the caller's problem, and a
    # caller that only reads the exit code has to be told.
    class UndeletableSsm(FakeSsm):
        def delete_document(self, **kwargs: object) -> dict[str, object]:
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "DeleteDocument"
            )

    patch_client(UndeletableSsm("Success"))
    argv = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
    ]

    assert test_runbook.main(argv) == 1
    # The report still names the leak, and names the document to go and delete.
    assert '"cleanedUp": false' in capsys.readouterr().out


def test_main_exit_zero_when_cleanup_was_waived(
    patch_client: Callable[[FakeSsm], None], tmp_path: Path
) -> None:
    # `--no-cleanup` asks for the document to stay, so `cleanedUp: false` is the
    # requested outcome rather than a leak, and must not turn a success into a 1.
    patch_client(FakeSsm("Success"))
    argv = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
        "--no-cleanup",
    ]

    assert test_runbook.main(argv) == 0


def test_main_exits_two_when_the_document_cannot_be_created(
    patch_client: Callable[[FakeSsm], None],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A CreateDocument refusal is a usage/AWS error with exit code 2. No
    # cleanup is needed because the transient document was never created.
    class UncreatableSsm(FakeSsm):
        def create_document(self, **kwargs: object) -> dict[str, object]:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                "CreateDocument",
            )

    patch_client(UncreatableSsm("Success"))
    argv = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
    ]

    assert test_runbook.main(argv) == 2
    assert "cannot create the test document" in capsys.readouterr().err


def test_main_exits_two_without_a_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("ASR_TEST_ASSUME_ROLE", raising=False)
    argv = ["test_runbook.py", "--script", _script_file(tmp_path)]

    assert test_runbook.main(argv) == 2
    assert "ASR_TEST_ASSUME_ROLE is required" in capsys.readouterr().err


def test_main_exit_two_on_every_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Five ways to call this wrong, all of which must exit 2 rather than crash.

    They are one test because they share a single contract: nothing reaches AWS
    and `SystemExit` from argparse is translated, not propagated. Two come from
    argparse (no `--script`, an unknown flag) and three from `main()`'s own reads
    (an unreadable script, a `--input-payload` that is not JSON, and one that is
    JSON but not an object) — the latter three are the ones that would otherwise
    surface as a traceback.
    """
    assert test_runbook.main(["test_runbook.py"]) == 2
    assert test_runbook.main(["test_runbook.py", "--nonesuch"]) == 2

    unreadable = ["test_runbook.py", "--script", str(tmp_path / "missing.py")]
    assert test_runbook.main(unreadable) == 2
    assert "cannot read" in capsys.readouterr().err

    bad_payload = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
        "--input-payload",
        "{not json",
    ]
    assert test_runbook.main(bad_payload) == 2
    assert capsys.readouterr().err

    # Valid JSON, wrong shape: a list parses fine and would only break later, on
    # `.items()`, once the transient document already existed.
    non_object_payload = [
        "test_runbook.py",
        "--script",
        _script_file(tmp_path),
        "--assume-role",
        ROLE,
        "--input-payload",
        '["BucketName"]',
    ]
    assert test_runbook.main(non_object_payload) == 2
    assert "must be a JSON object" in capsys.readouterr().err
