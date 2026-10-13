# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the full remediation-authoring flow against an AWS account.

Drives the complete remediation authoring lifecycle against a real AWS account:
  PRE-FLIGHT → READ → CREATE → VALIDATE → TEST → DEPLOY → EXECUTE → VERIFY → TEARDOWN

The flow follows the steps in `SKILL.md` and `authoring-loop.md`, uses the
bundled scripts, and checks the outcome of each stage.

Supports two AWS call modes:
  --mode boto3  (default) — call AWS through the SDK
  --mode cli              — call AWS through the AWS CLI

Requires:
  - ASR_SKILL_LIVE=1
  - ASR_TEST_ASSUME_ROLE=arn:aws:iam::<dev-acct>:role/<remediation-role>, whose
    account must be the one the credentials resolve to — pre-flight refuses a
    mismatch rather than creating the role and document somewhere unintended
  - AWS_REGION set to the target region
  - The ASR admin stack deployed (for document naming conventions)

Usage:
    ASR_SKILL_LIVE=1 \\
      ASR_TEST_ASSUME_ROLE=arn:aws:iam::<acct>:role/<remediation-role> \\
      AWS_REGION=us-east-1 \\
      python3 scripts/e2e_authoring_flow.py --mode boto3
      python3 scripts/e2e_authoring_flow.py --mode cli

Exit: 0 if all stages pass, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Literal, TypedDict

import boto3
from account_guard import account_id_from_arn, check_identity, partition_from_arn
from botocore.exceptions import ClientError


class AwsCliError(RuntimeError):
    """A non-zero exit from the `aws` CLI, carrying what failed and why.

    A named subclass rather than a bare `RuntimeError` so a caller can tell an
    AWS refusal from a bug in this file's own logic — `get_document_exists`
    catches it to mean "no such document" and would otherwise swallow any
    `RuntimeError`, including the one `runbook` raises for stages run out of
    order. Keeping `command` and `stderr` as attributes means the message stays
    readable while the detail is still available to a handler.
    """

    def __init__(self, command: list[str], stderr: str) -> None:
        self.command = command
        self.stderr = stderr
        super().__init__(f"aws CLI failed: {' '.join(command)}: {stderr}")


class StageResult(TypedDict):
    """One stage's outcome, as printed in the run summary.

    Built only by `_ok`/`_fail`/`_skip` and read by `main` to decide the exit
    code, so the three keys are the contract between them.
    """

    stage: str
    status: Literal["PASS", "FAIL", "SKIP"]
    detail: str


class PreflightRefused(Exception):
    """Raised when pre-flight cannot confirm the target account."""


# Every AWS call in this file goes through one of the two callers below, so a
# failed call arrives as exactly one of these: `ClientError` from boto3, or
# `AwsCliError` from a non-zero `aws` exit. Naming the pair keeps the stage
# methods from swallowing a `KeyError` or an `AttributeError` in this file's own
# logic and reporting it as an AWS failure.
AWS_CALL_ERRORS = (ClientError, AwsCliError)

# Which caller the run uses. A typo here would silently select `CliAwsCaller`,
# so the run would still pass while testing the wrong host path. Mirrors `--mode`.
CallMode = Literal["boto3", "cli"]

SCRIPTS = Path(__file__).resolve().parent
SKILL_ROOT = SCRIPTS.parent
# Names follow the convention the Orchestrator actually resolves —
# ASR-{shortname}_{version}_{controlId} and
# SO0111-Remediate-{shortname}-{version}-{controlId}. The control ID is
# deliberately not a real Security Hub control, so nothing can trigger these.
CONTROL_ID = "E2ETest.1"
DOC_NAME = f"ASR-SC_2.0.0_{CONTROL_ID}"
ROLE_NAME = f"SO0111-Remediate-SC-2.0.0-{CONTROL_ID}"

# The runbook declares Finding as a required StringMap (the Orchestrator always
# sends it), so StartAutomationExecution rejects the run without a value. These
# steps never read it; a minimal finding map is enough to satisfy the parameter.
E2E_FINDING = json.dumps({"Id": f"e2e-authoring-flow/{CONTROL_ID}"})


def _ok(stage: str, detail: str = "") -> StageResult:
    return {"stage": stage, "status": "PASS", "detail": detail}


def _fail(stage: str, detail: str) -> StageResult:
    return {"stage": stage, "status": "FAIL", "detail": detail}


def _skip(stage: str, detail: str) -> StageResult:
    return {"stage": stage, "status": "SKIP", "detail": detail}


# ---------------------------------------------------------------------------
# AWS call abstractions
# ---------------------------------------------------------------------------


class BotoAwsCaller:
    """Call AWS through boto3."""

    def __init__(self, region: str) -> None:
        self.region = region
        self.ssm = boto3.client("ssm", region_name=region)
        self.iam = boto3.client("iam")
        self.sts = boto3.client("sts", region_name=region)

    def get_caller_identity(self) -> dict[str, Any]:
        """The `sts get-caller-identity` response, values left as `Any`.

        Not `dict[str, str]`, which this was: the response also carries
        `ResponseMetadata`, whose value is a nested dict, so the narrower
        annotation described a shape the API never returns. Not a `TypedDict` of
        the two fields this flow reads (`Account`, `Arn`) either — `check_identity`
        takes the response *unvalidated* and fails closed on any shape it does not
        recognise, so declaring `Account: str` here would assert the validation
        that deliberately happens there.
        """
        identity: dict[str, Any] = self.sts.get_caller_identity()
        return identity

    def list_documents(self) -> list[str]:
        resp = self.ssm.list_documents(
            Filters=[
                {"Key": "Owner", "Values": ["Self"]},
                {"Key": "DocumentType", "Values": ["Automation"]},
                {"Key": "Name", "Values": ["ASR-"]},
            ],
        )
        return [d["Name"] for d in resp.get("DocumentIdentifiers", [])]

    def get_document_exists(self, name: str) -> bool:
        try:
            self.ssm.get_document(Name=name)
            return True
        except self.ssm.exceptions.InvalidDocument:
            return False

    def create_role(
        self, role_name: str, trust: dict[str, Any], description: str
    ) -> None:
        self.iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description=description,
        )

    def put_role_policy(
        self, role_name: str, policy_name: str, policy: dict[str, Any]
    ) -> None:
        self.iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy),
        )

    def create_document(self, name: str, content: str) -> None:
        self.ssm.create_document(
            Name=name,
            DocumentType="Automation",
            DocumentFormat="YAML",
            Content=content,
            TargetType="/",
        )

    def describe_document_status(self, name: str) -> str:
        status: str = self.ssm.describe_document(Name=name)["Document"]["Status"]
        return status

    def start_automation(self, doc_name: str, role_arn: str) -> str:
        resp = self.ssm.start_automation_execution(
            DocumentName=doc_name,
            Parameters={
                "AutomationAssumeRole": [role_arn],
                "Finding": [E2E_FINDING],
            },
        )
        execution_id: str = resp["AutomationExecutionId"]
        return execution_id

    def get_automation_status(self, execution_id: str) -> tuple[str, str]:
        info = self.ssm.get_automation_execution(AutomationExecutionId=execution_id)
        execution = info["AutomationExecution"]
        return execution["AutomationExecutionStatus"], execution.get(
            "FailureMessage", ""
        )

    def delete_document(self, name: str) -> None:
        self.ssm.delete_document(Name=name)

    def delete_role(self, role_name: str, policy_name: str) -> None:
        try:
            self.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError:
            # An absent inline policy is fine — the role still has to go.
            pass
        self.iam.delete_role(RoleName=role_name)


class CliAwsCaller:
    """Calls AWS via the `aws` CLI — simulates the Claude Code / Codex path."""

    def __init__(self, region: str) -> None:
        self.region = region

    def _run(self, cmd: list[str]) -> Any:
        """Run an `aws` command and parse its JSON.

        `Any` rather than `dict[str, Any]`: a `--query` projection returns a bare
        JSON list, which `list_documents` relies on. The old `dict` annotation was
        simply wrong about that, and narrowing it here would only push the cast
        into each caller — they know the shape their own command returns.
        """
        full_cmd = ["aws"] + cmd + ["--region", self.region, "--output", "json"]
        result = subprocess.run(full_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise AwsCliError(full_cmd, result.stderr.strip() or result.stdout.strip())
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def _run_no_output(self, cmd: list[str]) -> None:
        full_cmd = ["aws"] + cmd + ["--region", self.region]
        result = subprocess.run(full_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise AwsCliError(full_cmd, result.stderr.strip() or result.stdout.strip())

    def get_caller_identity(self) -> dict[str, Any]:
        """As `BotoAwsCaller.get_caller_identity`; see there for the `Any` values.

        `_run` returns whatever JSON the CLI printed, so the `isinstance` guard is
        what makes the `dict` half of the annotation true rather than assumed. An
        empty dict reaches `check_identity`, which also refuses responses of the
        wrong shape.
        """
        identity = self._run(["sts", "get-caller-identity"])
        return identity if isinstance(identity, dict) else {}

    def list_documents(self) -> list[str]:
        resp = self._run(
            [
                "ssm",
                "list-documents",
                "--filters",
                "Key=Owner,Values=Self",
                "Key=DocumentType,Values=Automation",
                "Key=Name,Values=ASR-",
                "--query",
                "DocumentIdentifiers[].Name",
            ]
        )
        return resp if isinstance(resp, list) else []

    def get_document_exists(self, name: str) -> bool:
        try:
            self._run(["ssm", "get-document", "--name", name])
            return True
        except AwsCliError:
            return False

    def create_role(
        self, role_name: str, trust: dict[str, Any], description: str
    ) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(trust, f)
            trust_path = f.name
        try:
            self._run_no_output(
                [
                    "iam",
                    "create-role",
                    "--role-name",
                    role_name,
                    "--assume-role-policy-document",
                    f"file://{trust_path}",
                    "--description",
                    description,
                ]
            )
        finally:
            os.unlink(trust_path)

    def put_role_policy(
        self, role_name: str, policy_name: str, policy: dict[str, Any]
    ) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(policy, f)
            policy_path = f.name
        try:
            self._run_no_output(
                [
                    "iam",
                    "put-role-policy",
                    "--role-name",
                    role_name,
                    "--policy-name",
                    policy_name,
                    "--policy-document",
                    f"file://{policy_path}",
                ]
            )
        finally:
            os.unlink(policy_path)

    def create_document(self, name: str, content: str) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(content)
            content_path = f.name
        try:
            self._run_no_output(
                [
                    "ssm",
                    "create-document",
                    "--name",
                    name,
                    "--document-type",
                    "Automation",
                    "--document-format",
                    "YAML",
                    "--content",
                    f"file://{content_path}",
                    "--target-type",
                    "/",
                ]
            )
        finally:
            os.unlink(content_path)

    def describe_document_status(self, name: str) -> str:
        # No `--output text` here, deliberately: `_run` appends `--output json`
        # and the last `--output` on the command line wins, so a text request
        # would be a dead argument that reads as though it were in force — and
        # if it ever did win, `json.loads` would raise on the bare word. With
        # `--query`, a scalar's JSON form is a quoted string, which `json.loads`
        # returns as a `str`.
        resp = self._run(
            [
                "ssm",
                "describe-document",
                "--name",
                name,
                "--query",
                "Document.Status",
            ]
        )
        return resp if isinstance(resp, str) else "Unknown"

    def start_automation(self, doc_name: str, role_arn: str) -> str:
        resp = self._run(
            [
                "ssm",
                "start-automation-execution",
                "--document-name",
                doc_name,
                "--parameters",
                json.dumps(
                    {
                        "AutomationAssumeRole": [role_arn],
                        "Finding": [E2E_FINDING],
                    }
                ),
            ]
        )
        execution_id: str = resp["AutomationExecutionId"]
        return execution_id

    def get_automation_status(self, execution_id: str) -> tuple[str, str]:
        resp = self._run(
            [
                "ssm",
                "get-automation-execution",
                "--automation-execution-id",
                execution_id,
            ]
        )
        execution = resp["AutomationExecution"]
        return execution["AutomationExecutionStatus"], execution.get(
            "FailureMessage", ""
        )

    def delete_document(self, name: str) -> None:
        self._run_no_output(["ssm", "delete-document", "--name", name])

    def delete_role(self, role_name: str, policy_name: str) -> None:
        try:
            self._run_no_output(
                [
                    "iam",
                    "delete-role-policy",
                    "--role-name",
                    role_name,
                    "--policy-name",
                    policy_name,
                ]
            )
        except AwsCliError:
            # An absent inline policy is fine — the role still has to go.
            pass
        self._run_no_output(["iam", "delete-role", "--role-name", role_name])


class AuthoringFlowRunner:
    """Drives the full authoring loop and collects results per stage."""

    def __init__(
        self,
        assume_role: str,
        *,
        region: str,
        mode: CallMode = "boto3",
        keep_artifacts: bool = False,
    ) -> None:
        self.assume_role = assume_role
        self.region = region
        self.mode = mode
        self.keep_artifacts = keep_artifacts
        self.results: list[StageResult] = []
        self.workspace = Path(tempfile.mkdtemp(prefix="asr-e2e-"))
        self.aws: BotoAwsCaller | CliAwsCaller = (
            BotoAwsCaller(region) if mode == "boto3" else CliAwsCaller(region)
        )
        self._artifacts_created: list[str] = []
        self.runbook_path: Path | None = None

    @property
    def runbook(self) -> Path:
        """The generated runbook, for stages that must have one.

        `_create` sets `runbook_path` and every later stage reads it, so the
        ordering in `run_all` is load-bearing. Going through here turns a stage
        run out of order into a named error instead of a `NoneType` traceback.
        """
        if self.runbook_path is None:
            raise RuntimeError(
                "_create must run before any stage that reads the runbook"
            )
        return self.runbook_path

    @property
    def partition(self) -> str:
        """The ARN partition to build ARNs in, read off the assume-role ARN.

        The two ARNs this run constructs — the Orchestrator principal in the trust
        policy, and the role it passes to `StartAutomationExecution` — have to sit
        in the same partition as the role the caller named, so that ARN is the
        source rather than a literal `aws`. On GovCloud or in China a hard-coded
        partition produced a principal that does not exist, and the trust policy
        was rejected.

        `_preflight` refuses a run whose assume-role ARN has no partition, so this
        raising is the same out-of-order guard as `runbook` above, not a real path.
        """
        partition = partition_from_arn(self.assume_role)
        if not partition:
            raise RuntimeError(
                "_preflight must run before any stage that builds an ARN"
            )
        return partition

    def run_all(self) -> list[StageResult]:
        """Execute all stages, always running teardown."""
        try:
            self._preflight()
            self._read()
            self._create()
            self._validate_skeleton()
            self._fill_steps()
            self._validate_complete()
            self._test_skip_execution()
            self._deploy_role()
            self._deploy_document()
            self._execute()
            self._teardown()
        except PreflightRefused:
            # `_preflight` has already recorded a precise failure; an
            # "unexpected" entry on top of it would bury the reason. Teardown
            # still runs, so the temp workspace goes away.
            self._teardown()
        except Exception as err:  # noqa: BLE001
            self.results.append(_fail("unexpected", str(err)))
            self._teardown()
        return self.results

    def _preflight(self) -> None:
        """Pre-flight: confirm the credentials are for the account the caller named.

        Fails closed, via the same `account_guard` check `deploy_stack.py` uses —
        this run creates an IAM role, an SSM document, and an automation
        execution, so a marker scan that passes every account without "prod" in
        the ARN is not enough. The account comes from the `ASR_TEST_ASSUME_ROLE`
        ARN, which is required and must name a role in the target account for SSM
        to assume it, so the caller has already said which account this is for.

        Mirrors `references/authoring-loop.md`, which has no health-check step —
        the later phases fail on their own if a script or dependency is missing.
        """
        expected_account = account_id_from_arn(self.assume_role)
        if not expected_account:
            self.results.append(
                _fail(
                    "preflight:identity",
                    f"could not read an account ID out of the assume-role ARN "
                    f"{self.assume_role!r} — cannot confirm which account this run "
                    f"is for",
                )
            )
            raise PreflightRefused("assume-role ARN carries no account ID")

        # The account check above tolerates an empty partition field, and the
        # stages that build ARNs cannot. Refusing here keeps the failure ahead of
        # the IAM role rather than in the middle of creating it.
        if not partition_from_arn(self.assume_role):
            self.results.append(
                _fail(
                    "preflight:identity",
                    f"could not read a partition out of the assume-role ARN "
                    f"{self.assume_role!r} — cannot build ARNs for this run",
                )
            )
            raise PreflightRefused("assume-role ARN carries no partition")

        identity = self.aws.get_caller_identity()
        is_safe, message = check_identity(identity, expected_account)
        if not is_safe:
            self.results.append(_fail("preflight:identity", message))
            raise PreflightRefused(message)

        self.results.append(_ok("preflight", f"{message}, mode={self.mode}"))

    def _read(self) -> None:
        """READ: verify we can list runbooks and identify a gap."""
        docs = self.aws.list_documents()
        count = len(docs)
        # Confirm our test control doesn't already exist
        if self.aws.get_document_exists(DOC_NAME):
            self.results.append(
                _fail(
                    "read",
                    f"Document {DOC_NAME} already exists — leftover from prior run?",
                )
            )
            return

        self.results.append(
            _ok("read", f"Listed {count} ASR docs; {CONTROL_ID} has no coverage")
        )

    def _create(self) -> None:
        """CREATE: run generate_runbook.py."""
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "generate_runbook.py"),
                "--control-id",
                CONTROL_ID,
                "--description",
                "E2E test runbook for authoring flow verification",
                "--workspace-root",
                str(self.workspace),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.results.append(_fail("create", result.stderr or result.stdout))
            return
        output = json.loads(result.stdout)
        created = output.get("created", [])
        if not created:
            self.results.append(_fail("create", "No files created"))
            return
        # Find the YAML
        self.runbook_path = next(
            (Path(f) for f in created if f.endswith(".yaml")), None
        )
        if not self.runbook_path:
            self.results.append(_fail("create", "No YAML in created files"))
            return
        self.results.append(_ok("create", f"Generated {len(created)} files"))

    def _validate_skeleton(self) -> None:
        """VALIDATE (skeleton): confirm it fails on empty mainSteps."""
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "validate_runbook.py"),
                str(self.runbook_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            self.results.append(
                _fail(
                    "validate:skeleton",
                    "Skeleton passed validation — should have failed",
                )
            )
            return
        if result.returncode == 1:
            output = json.loads(result.stdout)
            errors = output.get("errors", [])
            has_main_steps_error = any("mainSteps" in e for e in errors)
            if has_main_steps_error:
                self.results.append(
                    _ok("validate:skeleton", "Correctly rejected empty mainSteps")
                )
            else:
                self.results.append(
                    _fail("validate:skeleton", f"Failed for wrong reason: {errors}")
                )
        else:
            self.results.append(
                _fail("validate:skeleton", f"Unexpected exit code {result.returncode}")
            )

    def _fill_steps(self) -> None:
        """Fill in mainSteps with a minimal valid remediation + verify step."""
        # See validate_runbook.py for why this is an ignore and not types-PyYAML.
        import yaml  # type: ignore[import-untyped]

        with open(self.runbook) as f:
            doc = yaml.safe_load(f)

        doc["parameters"]["AutomationAssumeRole"] = {
            "type": "String",
            "description": "(Required) The ARN of the role that allows Automation to perform the actions on your behalf.",
            "allowedPattern": "^arn:(?:aws|aws-us-gov|aws-cn):iam::\\d{12}:role/[\\w+=,.@-]+$",
        }
        # The Orchestrator sends only Finding and AutomationAssumeRole, so a custom
        # runbook must declare Finding or it fails the orchestrator-parameters check.
        doc["parameters"]["Finding"] = {
            "type": "StringMap",
            "description": "(Required) The Security Hub finding that triggered the remediation.",
        }
        doc["mainSteps"] = [
            {
                "name": "DescribeTestDocument",
                "action": "aws:executeAwsApi",
                "timeoutSeconds": 600,
                "isEnd": False,
                "isCritical": True,
                "inputs": {
                    "Service": "ssm",
                    "Api": "DescribeDocument",
                    "Name": DOC_NAME,
                },
                "outputs": [
                    {
                        "Name": "DocumentStatus",
                        "Selector": "$.Document.Status",
                        "Type": "String",
                    }
                ],
            },
            {
                "name": "VerifyDocumentActive",
                "action": "aws:assertAwsResourceProperty",
                "timeoutSeconds": 600,
                "isEnd": True,
                "inputs": {
                    "Service": "ssm",
                    "Api": "DescribeDocument",
                    "Name": DOC_NAME,
                    "PropertySelector": "$.Document.Status",
                    "DesiredValues": ["Active"],
                },
            },
        ]

        with open(self.runbook, "w") as f:
            yaml.dump(doc, f, default_flow_style=False, sort_keys=False)

        self.results.append(
            _ok(
                "fill_steps",
                "Added 2 steps: DescribeTestDocument + VerifyDocumentActive",
            )
        )

    def _validate_complete(self) -> None:
        """VALIDATE (complete): the filled runbook must pass strict validation."""
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "validate_runbook.py"),
                str(self.runbook_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            self.results.append(_ok("validate:complete", "Passes strict validation"))
        else:
            self.results.append(_fail("validate:complete", result.stdout.strip()))

    def _test_skip_execution(self) -> None:
        """TEST: run test_runbook.py to confirm SSM accepts the schema."""
        import types

        import test_runbook

        args = types.SimpleNamespace(
            script="e2e",
            script_body="def handler(event, context):\n    return {'ok': True}\n",
            handler="handler",
            runtime="python3.11",
            input_payload=None,
            timeout=180,
            assume_role=self.assume_role,
            control_id=CONTROL_ID,
            document_name=None,
            cleanup=True,
        )
        result = test_runbook.run(args)
        if result.get("cleanedUp"):
            self.results.append(
                _ok("test", f"status={result.get('status')}, cleanedUp=True")
            )
        else:
            self.results.append(_fail("test", f"Cleanup failed: {result}"))

    def _deploy_role(self) -> None:
        """DEPLOY (a): create IAM role per remediation-iam.md."""
        account = self.aws.get_caller_identity()["Account"]
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ssm.amazonaws.com",
                        "AWS": (
                            f"arn:{self.partition}:iam::{account}"
                            ":role/SO0111-ASR-Orchestrator-Member"
                        ),
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ssm:DescribeDocument", "ssm:GetDocument"],
                    "Resource": "*",
                }
            ],
        }
        try:
            self.aws.create_role(
                ROLE_NAME,
                trust,
                f"ASR custom remediation role for {CONTROL_ID} (e2e test)",
            )
            self._artifacts_created.append(f"iam:role:{ROLE_NAME}")
            self.aws.put_role_policy(
                ROLE_NAME, "ASR-Custom-Runbook-Remediation", policy
            )
            # IAM roles take ~10s to propagate before SSM can assume them.
            time.sleep(10)
            self.results.append(_ok("deploy:role", f"Created {ROLE_NAME}"))
        except AWS_CALL_ERRORS as err:
            if "EntityAlreadyExists" in str(err) or "already exists" in str(err):
                self.results.append(
                    _ok("deploy:role", f"{ROLE_NAME} already exists (reusing)")
                )
                self._artifacts_created.append(f"iam:role:{ROLE_NAME}")
            else:
                self.results.append(_fail("deploy:role", str(err)))

    def _deploy_document(self) -> None:
        """DEPLOY (b): create SSM Automation document."""
        with open(self.runbook) as f:
            content = f.read()

        try:
            self.aws.create_document(DOC_NAME, content)
            self._artifacts_created.append(f"ssm:doc:{DOC_NAME}")
            # Wait for Active
            status = "Unknown"
            for _ in range(10):
                status = self.aws.describe_document_status(DOC_NAME)
                if status == "Active":
                    break
                time.sleep(1)
            if status != "Active":
                # A document stuck in Creating or landed in Failed is a real
                # deployment failure, and EXECUTE would fail on it anyway with a
                # less obvious message.
                self.results.append(
                    _fail(
                        "deploy:document",
                        f"Created {DOC_NAME} but status={status} after 10s",
                    )
                )
                return
            self.results.append(
                _ok("deploy:document", f"Created {DOC_NAME}, status=Active")
            )
        except AWS_CALL_ERRORS as err:
            if "AlreadyExists" in str(err) or "already exists" in str(err):
                self.results.append(
                    _ok("deploy:document", f"{DOC_NAME} already exists (reusing)")
                )
                self._artifacts_created.append(f"ssm:doc:{DOC_NAME}")
            else:
                self.results.append(_fail("deploy:document", str(err)))

    def _execute(self) -> None:
        """EXECUTE: start automation and poll for terminal state."""
        account = self.aws.get_caller_identity()["Account"]
        role_arn = f"arn:{self.partition}:iam::{account}:role/{ROLE_NAME}"

        try:
            execution_id = self.aws.start_automation(DOC_NAME, role_arn)
        except AWS_CALL_ERRORS as err:
            self.results.append(_fail("execute:start", str(err)))
            return

        # Poll for completion
        deadline = time.time() + 120
        status = "InProgress"
        failure_message = ""
        while time.time() < deadline:
            status, failure_message = self.aws.get_automation_status(execution_id)
            if status in ("Success", "Failed", "Cancelled", "TimedOut"):
                break
            time.sleep(5)

        if status == "Success":
            self.results.append(
                _ok("execute", f"executionId={execution_id}, status=Success")
            )
        else:
            self.results.append(
                _fail("execute", f"status={status}: {failure_message[:200]}")
            )

    def _teardown(self) -> None:
        """TEARDOWN: delete all created artifacts."""
        errors: list[str] = []

        # Delete SSM document
        if f"ssm:doc:{DOC_NAME}" in self._artifacts_created:
            try:
                self.aws.delete_document(DOC_NAME)
            except AWS_CALL_ERRORS as err:
                errors.append(f"ssm delete {DOC_NAME}: {err}")

        # Delete IAM role
        if f"iam:role:{ROLE_NAME}" in self._artifacts_created:
            try:
                self.aws.delete_role(ROLE_NAME, "ASR-Custom-Runbook-Remediation")
            except AWS_CALL_ERRORS as err:
                errors.append(f"iam delete {ROLE_NAME}: {err}")

        # Clean workspace
        if not self.keep_artifacts and self.workspace.exists():
            shutil.rmtree(self.workspace, ignore_errors=True)

        if errors:
            self.results.append(_fail("teardown", "; ".join(errors)))
        else:
            self.results.append(_ok("teardown", "All artifacts deleted"))


def main() -> int:
    parser = argparse.ArgumentParser(description="E2E authoring flow test")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    parser.add_argument(
        "--mode",
        choices=["boto3", "cli"],
        default="boto3",
        help="AWS call mode: boto3 (Kiro MCP path) or cli (Claude Code / Codex path)",
    )
    parser.add_argument(
        "--keep-artifacts", action="store_true", help="Don't delete test artifacts"
    )
    args = parser.parse_args()

    if os.environ.get("ASR_SKILL_LIVE") != "1":
        print("Set ASR_SKILL_LIVE=1 to run this test (requires real AWS).")
        return 1

    assume_role = os.environ.get("ASR_TEST_ASSUME_ROLE", "")
    if not assume_role:
        print("Set ASR_TEST_ASSUME_ROLE to the role SSM should assume.")
        return 1

    region = os.environ.get("AWS_REGION") or os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1"
    )

    # argparse `choices` constrains this at run time but types it `str`.
    mode: CallMode = "cli" if args.mode == "cli" else "boto3"
    runner = AuthoringFlowRunner(
        assume_role, region=region, mode=mode, keep_artifacts=args.keep_artifacts
    )
    results = runner.run_all()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        passed = 0
        failed = 0
        for r in results:
            icon = (
                "✓"
                if r["status"] == "PASS"
                else ("•" if r["status"] == "SKIP" else "✗")
            )
            detail = f": {r['detail']}" if r["detail"] else ""
            print(f"  {icon} {r['stage']}{detail}")
            if r["status"] == "PASS":
                passed += 1
            elif r["status"] == "FAIL":
                failed += 1
        print(f"\n{passed} passed, {failed} failed.")

    return 0 if all(r["status"] != "FAIL" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
