# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/deploy_stack.py.

The script's own AWS calls are live-only, so what is worth testing here is the
decision logic in front of them: which accounts it refuses to touch, and which
inputs it refuses to pass on to the buckets and stacks.

Two isolation measures make that safe. `aws` is replaced by a stub executable on
PATH, so the subprocess boundary runs for real without reaching AWS; and the
module's `deployment/dev/` path constants are redirected into `tmp_path`, so no
test can overwrite a developer's `local-config.json` or invoke the real
`deploy-dev.sh`. The stub deploy script touches a marker file, which is how the
refusal tests assert that nothing was deployed.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Protocol

import deploy_stack
import pytest

DEV_ACCOUNT = "111111111111"
OTHER_ACCOUNT = "999999999999"
DEV_ARN = f"arn:aws:sts::{DEV_ACCOUNT}:assumed-role/asr-authoring/session"


def _completed(
    cmd: list[str], *, returncode: int, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    """Build the CompletedProcess `deploy_stack._run` returns, for stubbing it."""
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


_AWS_STUB = '''#!/usr/bin/env python3
"""Stand-in for the `aws` CLI: answers sts, fails describe-stacks, else exits 0."""
import sys

argv = sys.argv[1:]
if argv[:2] == ["sts", "get-caller-identity"]:
    sys.stderr.write({stderr!r})
    sys.stdout.write({stdout!r})
    sys.exit({returncode})
if argv[:2] == ["cloudformation", "describe-stacks"]:
    sys.stderr.write("Stack does not exist\\n")
    sys.exit(254)
sys.exit(0)
'''


@pytest.fixture(autouse=True)
def deploy_script_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the module's real `deployment/dev/` paths into `tmp_path`.

    Returns the path the stub deploy script touches when it runs, so a test can
    assert the difference between "refused" and "refused, but deployed anyway".
    """
    marker = tmp_path / "deploy-script-ran"
    stub = tmp_path / "deploy-dev.sh"
    stub.write_text(f'#!/bin/sh\ntouch "{marker}"\n', encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)

    monkeypatch.setattr(deploy_stack, "DEV_DIR", tmp_path)
    monkeypatch.setattr(deploy_stack, "CONFIG_FILE", tmp_path / "local-config.json")
    monkeypatch.setattr(deploy_stack, "DEPLOY_SCRIPT", stub)
    return marker


class FakeAws(Protocol):
    """Installs the stub `aws` for one test, with the identity it should report."""

    def __call__(
        self,
        *,
        account: str = ...,
        arn: str = ...,
        returncode: int = ...,
        stderr: str = ...,
        stdout: str | None = ...,
    ) -> None: ...


@pytest.fixture()
def fake_aws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeAws:
    """Install a stub `aws` on PATH, reporting the identity a test asks for."""

    def install(
        *,
        account: str = DEV_ACCOUNT,
        arn: str = DEV_ARN,
        returncode: int = 0,
        stderr: str = "",
        stdout: str | None = None,
    ) -> None:
        if stdout is None:
            stdout = json.dumps(
                {"Account": account, "Arn": arn, "UserId": "AIDAEXAMPLE"}
            )
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        script = bin_dir / "aws"
        script.write_text(
            _AWS_STUB.format(stdout=stdout, stderr=stderr, returncode=returncode),
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    return install


def _write_config(config: Any) -> None:
    deploy_stack.CONFIG_FILE.write_text(json.dumps(config), encoding="utf-8")


def _init_argv(account_id: str = DEV_ACCOUNT) -> list[str]:
    return [
        "init",
        "--account-id",
        account_id,
        "--region",
        "us-east-1",
        "--email",
        "dev@example.com",
    ]


def test_init_refuses_credentials_for_another_account(fake_aws: FakeAws) -> None:
    # The check that matters: naming one account while holding credentials for
    # another must stop, not quietly bootstrap whichever account is configured.
    fake_aws(account=OTHER_ACCOUNT, arn=f"arn:aws:iam::{OTHER_ACCOUNT}:role/Admin")

    assert deploy_stack.main(_init_argv(DEV_ACCOUNT)) == 1
    assert not deploy_stack.CONFIG_FILE.exists()


def test_init_refuses_a_production_looking_arn(fake_aws: FakeAws) -> None:
    # Right account, but the ARN says production — the second gate.
    fake_aws(arn=f"arn:aws:iam::{DEV_ACCOUNT}:role/prod-deployer")

    assert deploy_stack.main(_init_argv()) == 1
    assert not deploy_stack.CONFIG_FILE.exists()


@pytest.mark.parametrize(
    "identity",
    [
        pytest.param({"stdout": "not json at all"}, id="unparseable"),
        pytest.param({"stdout": "[]"}, id="not-an-object"),
        pytest.param({"account": "", "arn": DEV_ARN}, id="no-account"),
        pytest.param(
            {"returncode": 255, "stderr": "ExpiredToken"}, id="invalid-credentials"
        ),
    ],
)
def test_init_refuses_when_the_account_cannot_be_confirmed(
    fake_aws: FakeAws, identity: dict[str, Any]
) -> None:
    # Anything that leaves the account unproven fails closed.
    fake_aws(**identity)

    assert deploy_stack.main(_init_argv()) == 1
    assert not deploy_stack.CONFIG_FILE.exists()


@pytest.mark.parametrize(
    "bad_id", ["", "12345", "1234567890123", "12345678901a", "111111111111 "]
)
def test_init_refuses_a_malformed_account_id(fake_aws: FakeAws, bad_id: str) -> None:
    # A malformed ID would land in S3 bucket names, and there would be nothing
    # meaningful to check the credentials against.
    fake_aws(account=bad_id, arn=f"arn:aws:iam::{bad_id}:role/dev")

    assert deploy_stack.main(_init_argv(bad_id)) == 2
    assert not deploy_stack.CONFIG_FILE.exists()


def test_init_writes_config_when_the_account_matches(fake_aws: FakeAws) -> None:
    fake_aws()

    assert deploy_stack.main(_init_argv()) == 0

    config = json.loads(deploy_stack.CONFIG_FILE.read_text(encoding="utf-8"))
    assert config["accountId"] == DEV_ACCOUNT
    assert config["region"] == "us-east-1"
    assert config["adminUserEmail"] == "dev@example.com"
    assert config["secHubAdminAccount"] == DEV_ACCOUNT
    # The buckets the deploy will use are derived from the verified account.
    assert config["templateBucketName"].endswith(f"-{DEV_ACCOUNT}-reference")
    assert config["assetBucketName"].endswith(f"-{DEV_ACCOUNT}-us-east-1")


@pytest.mark.parametrize("command", ["deploy", "delete"])
@pytest.mark.parametrize(
    ("config", "reason"),
    [
        pytest.param({"accountId": OTHER_ACCOUNT}, "mismatch", id="other-account"),
        pytest.param({"region": "us-east-1"}, "absent", id="no-account-id"),
    ],
)
def test_stack_commands_refuse_an_unconfirmed_account(
    fake_aws: FakeAws,
    deploy_script_marker: Path,
    command: str,
    config: dict[str, str],
    reason: str,
) -> None:
    # Both stack-changing commands read the account from local-config.json, so a
    # config naming another account — or naming none — must stop before the
    # deploy script runs.
    fake_aws()
    _write_config(config)

    assert deploy_stack.main([command]) == 1
    assert not deploy_script_marker.exists(), f"deployed despite {reason} account"


@pytest.mark.parametrize("command", ["deploy", "status"])
def test_commands_report_missing_config_instead_of_guessing(command: str) -> None:
    assert deploy_stack.main([command]) == 1


def test_delete_without_config_has_nothing_to_do() -> None:
    # Nothing was ever created, so this is success, not an error.
    assert deploy_stack.main(["delete"]) == 0


def test_read_config_rejects_a_json_document_that_is_not_an_object() -> None:
    # Every caller indexes the result by key; a list would fail later with an
    # unrelated TypeError.
    _write_config([{"accountId": DEV_ACCOUNT}])

    with pytest.raises(ValueError, match="must contain a JSON object"):
        deploy_stack._read_config()


def test_read_config_returns_none_when_absent() -> None:
    assert deploy_stack._read_config() is None


def test_status_reports_stacks_that_do_not_exist(
    fake_aws: FakeAws, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_aws()
    _write_config(
        {"accountId": DEV_ACCOUNT, "region": "us-east-1", "namespace": "1234"}
    )

    assert deploy_stack.main(["status"]) == 0
    assert "NOT FOUND" in capsys.readouterr().out


def _member_config() -> dict[str, str]:
    return {
        "accountId": DEV_ACCOUNT,
        "region": "us-east-1",
        "namespace": "1234",
        "baseBucketName": f"asr-staging-1234-{DEV_ACCOUNT}",
        "templateBucketName": f"asr-staging-1234-{DEV_ACCOUNT}-reference",
        "solutionName": "automated-security-response-on-aws",
        "solutionVersion": "v4.0.0.dev",
        "secHubAdminAccount": DEV_ACCOUNT,
    }


def test_status_reports_an_overridden_region(
    fake_aws: FakeAws, capsys: pytest.CaptureFixture[str]
) -> None:
    # Without the override a member stack in a second Region reads as absent, which
    # is indistinguishable from never having deployed it.
    fake_aws()
    _write_config(_member_config())

    assert deploy_stack.main(["status", "--region", "us-west-2"]) == 0

    output = capsys.readouterr().out
    assert "us-west-2 (override)" in output
    # The reader needs to know that two of the three stacks are *expected* to be
    # missing there, or the report looks like a broken deployment.
    assert "Only the member stack is expected" in output


@pytest.mark.parametrize(
    "region", ["us-west-2", "eu-central-1", "us-gov-west-1", "ap-southeast-3"]
)
def test_region_arg_accepts_region_codes(region: str) -> None:
    assert deploy_stack._region_arg(region) == region


@pytest.mark.parametrize(
    "region",
    ["", "us-west", "US-WEST-2", "us-west-2/", "../x", "us west 2", "$(id)"],
)
def test_region_arg_rejects_anything_that_is_not_a_region_code(region: str) -> None:
    # The value is spliced into bucket names, the template URL and CLI arguments,
    # so it is refused at the boundary rather than surfacing as an S3 error later.
    with pytest.raises(argparse.ArgumentTypeError):
        deploy_stack._region_arg(region)


def test_deploy_member_rejects_a_malformed_region_before_anything_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        deploy_stack.main(["deploy-member", "--region", "not-a-region"])

    assert exit_info.value.code == 2
    assert "is not an AWS Region code" in capsys.readouterr().err


def test_repo_root_is_found_above_the_current_directory(
    solution_checkout: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The skill may be installed anywhere (a user-level ~/.kiro/skills, say); what
    # matters is the checkout the operator is standing in.
    monkeypatch.delenv("ASR_WORKSPACE_ROOT", raising=False)
    monkeypatch.chdir(solution_checkout / "source")

    assert deploy_stack.resolve_repo_root() == solution_checkout


def test_repo_root_honours_the_workspace_override(
    solution_checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASR_WORKSPACE_ROOT", str(solution_checkout))
    monkeypatch.chdir(tmp_path)

    assert deploy_stack.resolve_repo_root() == solution_checkout


def test_repo_root_refuses_an_override_that_is_not_a_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASR_WORKSPACE_ROOT", str(tmp_path))

    with pytest.raises(SystemExit, match="is not a checkout"):
        deploy_stack.resolve_repo_root()


def test_deploy_member_refuses_the_config_region(
    fake_aws: FakeAws, capsys: pytest.CaptureFixture[str]
) -> None:
    # The config Region belongs to `deploy`; two paths writing one stack would
    # disagree about its parameters.
    fake_aws()
    _write_config(_member_config())

    assert deploy_stack.main(["deploy-member", "--region", "us-east-1"]) == 2
    assert "Use 'deploy' for that Region" in capsys.readouterr().err


def test_deploy_member_refuses_an_unconfirmed_account(fake_aws: FakeAws) -> None:
    # Same account gate as every other writing command — a second Region is still a
    # write against live infrastructure.
    fake_aws(account=OTHER_ACCOUNT, arn=f"arn:aws:iam::{OTHER_ACCOUNT}:role/Admin")
    _write_config(_member_config())

    assert deploy_stack.main(["deploy-member", "--region", "us-west-2"]) == 1


def test_deploy_member_refuses_without_the_member_roles_stack(
    fake_aws: FakeAws, capsys: pytest.CaptureFixture[str]
) -> None:
    # The stub `aws` fails every describe-stacks, so the roles stack reads as absent.
    # Its IAM roles are what the member stack's runbooks assume, and they are created
    # once per account by the base deploy.
    fake_aws()
    _write_config(_member_config())

    assert deploy_stack.main(["deploy-member", "--region", "us-west-2"]) == 1
    assert "deploy the base stacks with 'deploy' first" in capsys.readouterr().err


def test_deploy_member_requires_a_build_before_staging_assets(
    fake_aws: FakeAws,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Lambda needs its code bucket in the function's Region, so the dist has to be
    # uploaded per Region — and there is nothing to upload before a build.
    fake_aws()
    _write_config(_member_config())
    monkeypatch.setattr(
        deploy_stack,
        "_describe_stack_status",
        lambda stack, *, region: "CREATE_COMPLETE",
    )
    monkeypatch.setattr(
        deploy_stack, "REGIONAL_ASSETS_DIR", tmp_path / "regional-s3-assets"
    )

    assert deploy_stack.main(["deploy-member", "--region", "us-west-2"]) == 1
    assert "no build output at" in capsys.readouterr().err


def test_deploy_member_refuses_collisions_before_staging_assets(
    fake_aws: FakeAws,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A create that CloudFormation will reject over pre-existing member resources must
    # be refused before the asset upload runs or a staging bucket is created, or the
    # operator pays for the upload and is left with a bucket to clean up.
    fake_aws()
    _write_config(_member_config())
    assets = tmp_path / "regional-s3-assets"
    assets.mkdir()
    monkeypatch.setattr(deploy_stack, "REGIONAL_ASSETS_DIR", assets)

    def describe(stack: str, *, region: str) -> str | None:
        # The roles stack exists in the config Region; the member stack does not yet
        # exist in the target Region, so this is a create.
        return "CREATE_COMPLETE" if stack.startswith("ASR-Member-Roles-") else None

    monkeypatch.setattr(deploy_stack, "_describe_stack_status", describe)
    monkeypatch.setattr(
        deploy_stack,
        "check_member_stack_collisions",
        lambda account_id, *, region: [f"S3 bucket so0111-asr-remediation-{region}-x"],
    )

    def must_not_stage(*args: object, **kwargs: object) -> None:
        raise AssertionError("assets were staged despite a collision")

    monkeypatch.setattr(deploy_stack, "_ensure_private_bucket", must_not_stage)
    # The upload script is the one subprocess this command starts directly (the sts
    # gate goes through `_run`), so its path standing in for a run is the sentinel.
    monkeypatch.setattr(deploy_stack, "UPLOAD_SCRIPT", tmp_path / "must-not-run.sh")

    assert deploy_stack.main(["deploy-member", "--region", "us-west-2"]) == 1
    err = capsys.readouterr().err
    assert "already holds member-stack resources" in err
    assert "asset upload" not in err


def test_collision_check_names_every_blocking_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CloudFormation says "Validation failed with 2 error(s)" and names nothing.

    Early Validation rejects the create without identifying the resources, so the
    operator gets a CREATE_FAILED stack and no lead. This check has to name them.
    """

    def fake_run(
        cmd: list[str], check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        stdout = ""
        if "list-policies" in cmd:
            stdout = (
                f"arn:aws:iam::{DEV_ACCOUNT}:policy/"
                "ASR-RemediationConfigBucketAccess-us-west-2"
            )
        elif "list-documents" in cmd:
            stdout = "ASR-EnableMacie\tASR-SC_2.0.0_S3.1"
        elif "describe-stacks" in cmd:
            stdout = "ASR-MEMBER-OLD-RunbookStackNoRoles-ABC"
        return _completed(cmd, returncode=0, stdout=stdout)

    monkeypatch.setattr(deploy_stack, "_run", fake_run)
    monkeypatch.setattr(
        deploy_stack,
        "_member_stack_document_names",
        lambda: frozenset({"ASR-EnableMacie", "ASR-SC_2.0.0_S3.1"}),
    )

    collisions = deploy_stack.check_member_stack_collisions(
        DEV_ACCOUNT, region="us-west-2"
    )

    assert collisions == [
        f"S3 bucket so0111-asr-remediation-us-west-2-{DEV_ACCOUNT}",
        "IAM managed policy ASR-RemediationConfigBucketAccess-us-west-2",
        "2 SSM documents the member stack creates (ASR-EnableMacie, ASR-SC_2.0.0_S3.1)",
        "DELETE_FAILED stack ASR-MEMBER-OLD-RunbookStackNoRoles-ABC "
        "(still claims its document names)",
    ]


def test_collision_check_ignores_custom_runbooks_the_stack_does_not_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A custom runbook authored with this skill shares the ASR- prefix.

    ASR-<Shortname>_<Version>_<ControlId> is not one of the member stack's documents,
    so its presence must not refuse a member deployment into that Region.
    """

    def fake_run(
        cmd: list[str], check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return _completed(
            cmd,
            returncode=255 if "head-bucket" in cmd else 0,
            stdout="ASR-Team_1.0.0_IAM.6" if "list-documents" in cmd else "",
        )

    monkeypatch.setattr(deploy_stack, "_run", fake_run)
    monkeypatch.setattr(
        deploy_stack,
        "_member_stack_document_names",
        lambda: frozenset({"ASR-EnableMacie", "ASR-SC_2.0.0_S3.1"}),
    )

    assert (
        deploy_stack.check_member_stack_collisions(DEV_ACCOUNT, region="us-west-2")
        == []
    )


def test_member_stack_document_names_come_from_the_built_templates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "playbooks").mkdir()
    (tmp_path / "automated-security-response-remediation-runbooks.template").write_text(
        '{"Resources": {"A": {"Properties": {"Name": "ASR-EnableMacie"}}}}'
    )
    (tmp_path / "playbooks" / "SCMemberStack.template").write_text(
        '{"Properties": {"Name":"ASR-SC_2.0.0_S3.1", "Other": "/Solutions/SO0111/x"}}'
    )
    (tmp_path / "playbooks" / "SCStack.template").write_text(
        '{"Properties": {"Name": "ASR-NotAMemberDocument"}}'
    )
    monkeypatch.setattr(deploy_stack, "GLOBAL_ASSETS_DIR", tmp_path)

    assert deploy_stack._member_stack_document_names() == frozenset(
        {"ASR-EnableMacie", "ASR-SC_2.0.0_S3.1"}
    )


def test_describe_stack_status_distinguishes_absent_from_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only "does not exist" means absent; anything else must not read as absent.

    Collapsing throttling or an expired session to None routed a transient error to
    create-stack against a stack that may well exist.
    """
    answers: dict[str, subprocess.CompletedProcess[str]] = {}

    def fake_run(
        cmd: list[str], check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return answers[cmd[cmd.index("--stack-name") + 1]]

    monkeypatch.setattr(deploy_stack, "_run", fake_run)
    answers["absent"] = _completed(
        [], returncode=254, stderr="Stack with id absent does not exist"
    )
    answers["throttled"] = _completed(
        [], returncode=254, stderr="An error occurred (Throttling)"
    )
    answers["garbled"] = _completed([], returncode=0, stdout="not json")
    answers["present"] = _completed(
        [], returncode=0, stdout='{"Stacks": [{"StackStatus": "CREATE_COMPLETE"}]}'
    )

    assert deploy_stack._describe_stack_status("absent", region="us-west-2") is None
    assert (
        deploy_stack._describe_stack_status("present", region="us-west-2")
        == "CREATE_COMPLETE"
    )
    with pytest.raises(deploy_stack.StackStatusUnavailable):
        deploy_stack._describe_stack_status("throttled", region="us-west-2")
    with pytest.raises(deploy_stack.StackStatusUnavailable):
        deploy_stack._describe_stack_status("garbled", region="us-west-2")


def test_deploy_member_stops_when_the_stack_state_is_unknown(
    fake_aws: FakeAws,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_aws()
    _write_config(_member_config())
    assets = tmp_path / "regional-s3-assets"
    assets.mkdir()
    monkeypatch.setattr(deploy_stack, "REGIONAL_ASSETS_DIR", assets)

    def describe(stack: str, *, region: str) -> str | None:
        if stack.startswith("ASR-Member-Roles-"):
            return "CREATE_COMPLETE"
        raise deploy_stack.StackStatusUnavailable("describe-stacks failed: Throttling")

    monkeypatch.setattr(deploy_stack, "_describe_stack_status", describe)

    def must_not_stage(*args: object, **kwargs: object) -> None:
        raise AssertionError("assets were staged with the stack state unknown")

    monkeypatch.setattr(deploy_stack, "_ensure_private_bucket", must_not_stage)

    assert deploy_stack.main(["deploy-member", "--region", "us-west-2"]) == 1
    err = capsys.readouterr().err
    assert "Throttling" in err
    assert "Retry once describe-stacks succeeds" in err


def test_deploy_member_refuses_a_stack_that_cannot_be_updated(
    fake_aws: FakeAws,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A create with --disable-rollback that failed still exists, so it used to be
    # taken for an update — which CloudFormation rejects, leaving the operator able
    # to neither create nor update. Name the way out instead.
    fake_aws()
    _write_config(_member_config())
    assets = tmp_path / "regional-s3-assets"
    assets.mkdir()
    monkeypatch.setattr(deploy_stack, "REGIONAL_ASSETS_DIR", assets)
    monkeypatch.setattr(
        deploy_stack,
        "_describe_stack_status",
        lambda stack, *, region: (
            "CREATE_COMPLETE"
            if stack.startswith("ASR-Member-Roles-")
            else "CREATE_FAILED"
        ),
    )

    def must_not_stage(*args: object, **kwargs: object) -> None:
        raise AssertionError("assets were staged for a stack that cannot be updated")

    monkeypatch.setattr(deploy_stack, "_ensure_private_bucket", must_not_stage)

    assert deploy_stack.main(["deploy-member", "--region", "us-west-2"]) == 1
    err = capsys.readouterr().err
    assert "is CREATE_FAILED" in err
    assert "delete-stack --stack-name ASR-Member-" in err


def test_collision_check_reports_a_stuck_stack_with_no_documents_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Emptying SSM does not release the names, so a clean listing must not pass.

    A DELETE_FAILED stack holds its `AWS::SSM::Document` resources at UPDATE_COMPLETE
    after the documents are deleted underneath it, and CloudFormation still rejects
    the next create with "already exists in stack". Reporting only the documents gave
    a false all-clear and cost a CREATE_FAILED stack.
    """

    def fake_run(
        cmd: list[str], check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return _completed(
            cmd,
            returncode=255 if "head-bucket" in cmd else 0,
            stdout=(
                "ASR-MEMBER-OLD-RunbookStackNoRoles-ABC"
                if "describe-stacks" in cmd
                else ""
            ),
        )

    monkeypatch.setattr(deploy_stack, "_run", fake_run)

    assert deploy_stack.check_member_stack_collisions(
        DEV_ACCOUNT, region="us-west-2"
    ) == [
        "DELETE_FAILED stack ASR-MEMBER-OLD-RunbookStackNoRoles-ABC "
        "(still claims its document names)"
    ]


def test_collision_check_is_silent_on_a_clean_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        cmd: list[str], check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return _completed(cmd, returncode=255 if "head-bucket" in cmd else 0)

    monkeypatch.setattr(deploy_stack, "_run", fake_run)

    assert (
        deploy_stack.check_member_stack_collisions(DEV_ACCOUNT, region="us-west-2")
        == []
    )


def test_member_parameters_keep_the_action_log_cloudtrail_off() -> None:
    # Its bucket name carries no Region segment, so enabling it in a second Region
    # collides with the first Region's bucket in S3's global namespace.
    parameters = dict(deploy_stack.MEMBER_PLAYBOOK_PARAMETERS)

    assert parameters["EnableCloudTrailForASRActionLog"] == "no"
    # The playbook selection must match deploy-dev.sh's MEMBER_PARAMS, or the two
    # Regions remediate different control sets from one admin stack.
    assert parameters["LoadSCMemberStack"] == "yes"
    assert [key for key, value in parameters.items() if value == "yes"] == [
        "LoadSCMemberStack"
    ]
