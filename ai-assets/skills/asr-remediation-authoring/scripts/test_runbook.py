#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test a candidate Python remediation script against a transient SSM document.

Lifecycle: CreateDocument -> StartAutomationExecution -> poll to terminal ->
DeleteDocument.

CRITICAL GUARANTEE: the transient document is deleted on EVERY exit path
(success, failure, timeout, exception, Ctrl-C) via a `finally` block — never
left for the caller to remember. This is why the step stays as code, not prose.

Usage:
    test_runbook.py --script <file.py> --assume-role <arn>
                    [--handler handler] [--runtime python3.11]
                    [--input-payload '{"k":"v"}'] [--timeout 300]
                    [--control-id S3.9] [--no-cleanup]

`--assume-role` falls back to $ASR_TEST_ASSUME_ROLE. Region from $AWS_REGION.
One of the two role inputs is required: the `aws:executeScript` sandbox does not
inherit AWS credentials from the process that starts the Automation execution.
The tool refuses a missing role before creating the transient document.
Exit codes: 0 = execution reached Success and the document was cleaned up,
1 = non-success/failure, or a requested cleanup that did not happen (the document
is still there), 2 = usage/error.
Prints a JSON report to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Protocol, TypedDict

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    print("test_runbook: requires boto3 (pip install boto3)", file=sys.stderr)
    raise SystemExit(2)

DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_RUNTIME = "python3.11"
DEFAULT_HANDLER = "handler"
POLL_INTERVAL_S = 3
DOCUMENT_NAME_PREFIX = "ASR-Custom-TestRemediation-"
TERMINAL = {"Success", "Failed", "TimedOut", "Cancelled"}

INCLUDE_RE = re.compile(r"^#?\s*%%INCLUDE=(?P<file>.*)%%$")
FMT_OFF_RE = re.compile(r"^#\s*fmt:\s*off$")
FMT_ON_RE = re.compile(r"^#\s*fmt:\s*on$")
FROM_COMMON_RE = re.compile(r"^from\s+common\.\w+\s+import")
COMMON_PREFIX = "common/"


def _find_common_dir(start: Path) -> Path | None:
    """Walk up from `start` for source/remediation_runbooks/scripts/common."""
    rel = Path("source/remediation_runbooks/scripts/common")
    for base in [start, *start.parents]:
        candidate = base / rel
        if (candidate / "snapshot_utils.py").is_file():
            return candidate
    return None


def resolve_includes(
    script_content: str, script_dir: Path, common_dir: Path | None
) -> str:
    """Expand `%%INCLUDE=` directives, stripping the fenced test-only `from common...`
    import, exactly as the build does. Returns content unchanged when there is no directive.
    """
    resolved: list[str] = []
    for line in script_content.split("\n"):
        match = INCLUDE_RE.match(line.strip())
        if not match:
            resolved.append(line)
            continue
        ref = match.group("file")
        if ref.startswith(COMMON_PREFIX):
            if common_dir is None:
                raise ValueError(
                    f"script has {line.strip()!r} but the common scripts dir was not found; "
                    "pass --common-dir pointing at source/remediation_runbooks/scripts/common"
                )
            include_path = common_dir / ref[len(COMMON_PREFIX) :]
        else:
            include_path = script_dir / ref
        try:
            include_content = include_path.read_text(encoding="utf-8")
        except OSError as err:
            raise ValueError(
                f"cannot read %%INCLUDE file {include_path}: {err}"
            ) from err
        # Strip the fenced `# fmt: off` / `from common...` / `# fmt: on` import block that
        # precedes the directive, requiring the import shape so an unrelated fence is safe.
        if resolved and FMT_ON_RE.match(resolved[-1].strip()):
            fence_end = len(resolved) - 1
            fence_start = fence_end - 1
            while fence_start >= 0 and not FMT_OFF_RE.match(
                resolved[fence_start].strip()
            ):
                fence_start -= 1
            if fence_start >= 0:
                body = resolved[fence_start + 1 : fence_end]
                first = next(
                    (fence_line for fence_line in body if fence_line.strip() != ""),
                    None,
                )
                if first is not None and FROM_COMMON_RE.match(first.strip()):
                    del resolved[fence_start : fence_end + 1]
        resolved.append(include_content.removesuffix("\n"))
    return "\n".join(resolved)


def build_document(
    runtime: str,
    handler: str,
    python_script: str,
    input_keys: list[str],
    timeout_seconds: int,
) -> str:
    param_lines = [
        "parameters:",
        "  AutomationAssumeRole:",
        "    type: String",
        "    description: IAM role SSM Automation assumes to run the script.",
    ]
    for k in input_keys:
        param_lines += [
            f"  {k}:",
            "    type: String",
            f'    description: "Input value for {k}."',
        ]

    if input_keys:
        input_payload = "\n".join(
            ["      InputPayload:"]
            + [f'        {k}: "{{{{ {k} }}}}"' for k in input_keys]
        )
    else:
        input_payload = "      InputPayload: {}"

    script_literal = "\n".join(
        f"          {line}" for line in python_script.split("\n")
    )

    header = [
        'schemaVersion: "0.3"',
        "description: Transient ASR remediation test runner (created by asr-remediation-authoring skill).",
        'assumeRole: "{{ AutomationAssumeRole }}"',
    ]

    return "\n".join(
        header
        + [
            "\n".join(param_lines),
            "mainSteps:",
            "  - name: RunCandidateScript",
            "    action: aws:executeScript",
            f"    timeoutSeconds: {timeout_seconds}",
            "    outputs:",
            "      - Name: Payload",
            "        Selector: $.Payload",
            "        Type: StringMap",
            "    inputs:",
            f"      Runtime: {runtime}",
            f"      Handler: {handler}",
            input_payload,
            "      Script: |",
            script_literal,
            "",
        ]
    )


def resolve_assume_role(explicit_assume_role: str | None) -> str:
    """Return the required SSM execution role or reject the run before AWS writes."""
    assume_role = explicit_assume_role or os.environ.get("ASR_TEST_ASSUME_ROLE")
    if not assume_role:
        raise ValueError(
            "--assume-role or ASR_TEST_ASSUME_ROLE is required: "
            "aws:executeScript does not inherit AWS credentials from the caller. "
            "Pass the exact remediation role with permissions for the handler's "
            "AWS API calls."
        )
    return assume_role


def generate_document_name(explicit: str | None, control_id: str | None) -> str:
    if explicit:
        return explicit
    slug = (
        "".join(c if c.isalnum() else "-" for c in control_id)
        if control_id
        else "adhoc"
    )
    suffix = format(int(time.time() * 1000), "x")
    return f"{DOCUMENT_NAME_PREFIX}{slug}-{suffix}"


class SsmAutomationClient(Protocol):
    """The one SSM call the polling loop makes.

    `Any` accepted a client for any service at all, which is worth narrowing here
    in particular: this is also the seam the tests substitute, so the parameter is
    where a stand-in learns what it has to provide. Keyword-only and capitalised
    to match the boto3 client it is handed at run time.
    """

    def get_automation_execution(
        self, *, AutomationExecutionId: str
    ) -> dict[str, Any]: ...


def wait_for_terminal(
    ssm: SsmAutomationClient, execution_id: str, timeout_seconds: int
) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds + 30
    while time.time() < deadline:
        resp = ssm.get_automation_execution(AutomationExecutionId=execution_id)
        execution = resp.get("AutomationExecution", {})
        if execution.get("AutomationExecutionStatus") in TERMINAL:
            return dict(execution)
        time.sleep(POLL_INTERVAL_S)
    raise TimeoutError(
        f"execution {execution_id} did not reach a terminal state within {timeout_seconds}s + 30s poll budget."
    )


def extract_payload(execution: dict[str, Any]) -> Any:
    steps = execution.get("StepExecutions") or [{}]
    step_payload = (steps[0].get("Outputs") or {}).get("Payload")
    if step_payload:
        try:
            return json.loads(step_payload[0])
        except (ValueError, IndexError):
            return step_payload[0] if step_payload else None
    candidate = (execution.get("Outputs") or {}).get("RunCandidateScript.Payload")
    if not candidate:
        return None
    try:
        return json.loads(candidate[0])
    except ValueError:
        return candidate[0]


class RunArgs(Protocol):
    """The attributes `run` reads off the parsed CLI namespace.

    A `Protocol` rather than a concrete class because the real argument is
    argparse's `Namespace`, which no annotation can describe — but `Any` hid a
    typo in any of these nine names until run time, mid-execution, with a
    transient SSM document already created. Structural typing also keeps the
    tests' `SimpleNamespace` valid without importing anything from here.
    """

    script_body: str
    handler: str
    runtime: str
    input_payload: str | None
    timeout: int
    assume_role: str | None
    control_id: str | None
    document_name: str | None
    cleanup: bool


class RunbookTestReport(TypedDict):
    """The JSON report `run` returns, printed to stdout and read by the agent.

    Named keys rather than `dict[str, Any]` because this shape is the tool's
    contract: `references/authoring-loop.md` tells the agent to read `status` and
    `failureMessage` out of it, and a renamed or dropped key should fail `mypy`
    here rather than read as `None` in a later phase.
    """

    documentName: str
    executionId: str | None
    status: str | None
    durationSeconds: float
    # Set on any failure, including one that only surfaced while deleting the
    # transient document — the execution can succeed and cleanup still fail.
    failureMessage: str | None
    # Whatever the handler returned, so genuinely unknown JSON.
    output: Any
    cleanedUp: bool


def run(args: RunArgs) -> RunbookTestReport:
    assume_role = resolve_assume_role(args.assume_role)
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    input_payload = json.loads(args.input_payload) if args.input_payload else {}
    # `json.loads` accepts any JSON value, but every use below treats the result
    # as a mapping, so a list or a scalar would only surface much later as an
    # `AttributeError` on `.items()` — after the document has been created. `main`
    # turns this into the same exit 2 as a malformed payload.
    if not isinstance(input_payload, dict):
        raise ValueError("--input-payload must be a JSON object")
    input_keys = list(input_payload.keys())
    document_name = generate_document_name(args.document_name, args.control_id)

    ssm = boto3.client("ssm", region_name=region) if region else boto3.client("ssm")

    content = build_document(
        args.runtime,
        args.handler,
        args.script_body,
        input_keys,
        args.timeout,
    )

    ssm.create_document(
        Name=document_name,
        DocumentType="Automation",
        DocumentFormat="YAML",
        Content=content,
        TargetType="/",
    )

    started = time.time()
    execution_id = None
    execution = None
    failure_message = None
    cleaned_up = False
    delete_error = None

    try:
        parameters: dict[str, list[str]] = {"AutomationAssumeRole": [assume_role]}
        for k, v in input_payload.items():
            parameters[k] = [v if isinstance(v, str) else json.dumps(v)]
        start = ssm.start_automation_execution(
            DocumentName=document_name, Parameters=parameters
        )
        execution_id = start.get("AutomationExecutionId")
        if not execution_id:
            raise RuntimeError(
                "StartAutomationExecution returned no AutomationExecutionId"
            )
        execution = wait_for_terminal(ssm, execution_id, args.timeout)
        if execution.get("AutomationExecutionStatus") != "Success":
            failure_message = execution.get("FailureMessage") or execution.get(
                "AutomationExecutionStatus"
            )
    # The failures this reports are the ones AWS can hand back: a rejected or
    # throttled call (ClientError), a broken endpoint or missing credentials
    # (BotoCoreError), no terminal state in the budget (TimeoutError), and an
    # execution that started without an id (RuntimeError). A bare `except
    # Exception` also swallowed our own bugs — a typo in `wait_for_terminal` came
    # back as a `failureMessage` reading like the candidate script had failed.
    # Those now raise, and the `finally` below still deletes the document.
    except (ClientError, BotoCoreError, TimeoutError, RuntimeError) as err:
        failure_message = str(err)
    finally:
        # THE GUARANTEE: always delete the transient document unless --no-cleanup.
        if args.cleanup:
            try:
                ssm.delete_document(Name=document_name)
                cleaned_up = True
            except (ClientError, BotoCoreError) as err:
                delete_error = str(err)

    return {
        "documentName": document_name,
        "executionId": execution_id,
        "status": execution.get("AutomationExecutionStatus") if execution else None,
        "durationSeconds": round(time.time() - started, 3),
        "failureMessage": failure_message or delete_error,
        "output": extract_payload(execution) if execution else None,
        "cleanedUp": cleaned_up,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="test_runbook.py")
    parser.add_argument(
        "--script",
        dest="script",
        required=True,
        help="Path to candidate Python handler file.",
    )
    parser.add_argument("--handler", default=DEFAULT_HANDLER)
    parser.add_argument("--runtime", default=DEFAULT_RUNTIME)
    parser.add_argument("--input-payload", dest="input_payload", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--assume-role",
        dest="assume_role",
        default=None,
        help="Required role SSM assumes for the execution; falls back to "
        "$ASR_TEST_ASSUME_ROLE.",
    )
    parser.add_argument("--control-id", dest="control_id", default=None)
    parser.add_argument("--document-name", dest="document_name", default=None)
    parser.add_argument(
        "--common-dir",
        dest="common_dir",
        default=None,
        help="Dir with snapshot_utils.py for %%INCLUDE expansion "
        "(default: nearest source/remediation_runbooks/scripts/common)",
    )
    parser.add_argument("--no-cleanup", dest="cleanup", action="store_false")
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else 2
    try:
        with open(args.script, encoding="utf-8") as fh:
            args.script_body = fh.read()
    except OSError as err:
        print(f"test_runbook: cannot read {args.script}: {err}", file=sys.stderr)
        return 2
    script_dir = Path(args.script).resolve().parent
    common_dir = (
        Path(args.common_dir).resolve()
        if args.common_dir
        else _find_common_dir(script_dir)
    )
    try:
        args.script_body = resolve_includes(args.script_body, script_dir, common_dir)
    except ValueError as err:
        print(f"test_runbook: {err}", file=sys.stderr)
        return 2
    try:
        result = run(args)
    except (ValueError, json.JSONDecodeError) as err:
        print(f"test_runbook: {err}", file=sys.stderr)
        return 2
    except (ClientError, BotoCoreError) as err:
        # `create_document` runs before `run`'s try/finally, so a rejected create
        # (AccessDeniedException) or a name collision (DocumentAlreadyExists) leaves
        # `run` uncaught — and the documented contract for that is exit 2, not a
        # traceback. Nothing was created on this path, so nothing needs deleting.
        print(f"test_runbook: cannot create the test document: {err}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, default=str))
    if result["status"] != "Success":
        return 1
    # A cleanup that was asked for and did not happen leaks a transient document,
    # and SSM has no TTL, so exiting 0 here would report a leak as a clean run. The
    # delete error is already in `failureMessage`.
    if args.cleanup and not result["cleanedUp"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
