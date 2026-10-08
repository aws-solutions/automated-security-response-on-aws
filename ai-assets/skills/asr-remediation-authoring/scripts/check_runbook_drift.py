#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Structural diff between a local runbook and the deployed SSM document.

Fetches the deployed document via ssm:GetDocument, then compares structurally
(whitespace / key ordering do not register as drift).

Usage:
    check_runbook_drift.py <document_name> <local_file> [--format YAML|JSON]
                           [--region <aws-region>]

The region defaults to `AWS_REGION` / `AWS_DEFAULT_REGION`, then to the boto3
default chain. The report always echoes the region it queried: `missing-remote`
against the wrong region is indistinguishable from a document that was never
deployed unless you check that field.

Exit codes: 0 = in sync, 1 = drift (or missing remote), 2 = usage/error.
Prints a JSON report to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Literal, TypedDict

# The two formats SSM accepts for an Automation document, and the only two values
# any function here is handed. The format `GetDocument` reports is a plain string
# the API chooses, and argparse accepts either case, so both are narrowed by
# `as_document_format` where they enter rather than carried around as a `str`.
DocumentFormat = Literal["YAML", "JSON"]

# Why the check ended where it did. A Literal because the agent branches on it:
# `missing-remote` means deploy, `differs` means redeploy, and the two
# `identical-*` values are the same verdict reached by different routes.
DriftReason = Literal[
    "missing-remote", "identical-text", "identical-structure", "differs"
]

# Which side of the comparison holds the value. Spelled as a Literal because the
# agent branches on it: "added" means the local file is ahead and needs deploying,
# "removed" means the deployed document has something the file does not.
DiffChangeType = Literal["added", "removed", "changed"]


class DiffEntry(TypedDict):
    """One structural difference between the local runbook and the deployed document.

    Named keys rather than `dict[str, Any]` because this is the part of the report
    the agent acts on — `path` says where to look, `changeType` says which side is
    ahead — so a renamed key should fail `mypy` here rather than read as a missing
    entry downstream. `local` and `remote` stay `Any`: they hold whatever the
    runbook had at that path, already passed through `truncate`.
    """

    path: str
    changeType: DiffChangeType
    local: Any
    remote: Any


class ReportIdentity(TypedDict):
    """What the report says about itself, on every exit path including failure."""

    documentName: str
    localFormat: DocumentFormat
    region: str


class RemoteDocumentMetadata(TypedDict, total=False):
    """What `describe_document` adds, once there is a deployed document to describe.

    Kept apart from `ReportIdentity`, and optional in the report, because the
    `missing-remote` exit returns before these exist. Both halves are spelled as
    types rather than left inferred because they are unpacked into the report
    literal, and `mypy` rejects `**` expansion of a plain `dict` there.
    """

    remoteFormat: str
    remoteLatestVersion: str | None
    remoteStatus: str | None


class DriftReport(ReportIdentity, RemoteDocumentMetadata):
    """The JSON report `check` returns, and the CLI prints to stdout.

    Named keys rather than `dict[str, Any]`, matching `GenerateResult` and
    `RunbookTestReport`: `authoring-loop.md` tells the agent to read `inSync` and
    `structuralDiff` out of this, so a renamed or dropped key should fail `mypy`
    here rather than read as `None` in a later phase.
    """

    inSync: bool
    reason: DriftReason
    structuralDiff: list[DiffEntry]


try:
    # See validate_runbook.py for why this is an ignore and not types-PyYAML.
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    print("check_runbook_drift: requires PyYAML (pip install pyyaml)", file=sys.stderr)
    raise SystemExit(2)
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover
    print("check_runbook_drift: requires boto3 (pip install boto3)", file=sys.stderr)
    raise SystemExit(2)

MAX_DIFF_ENTRIES = 100


def as_document_format(reported: str) -> DocumentFormat:
    """Narrow a format string from the API or the CLI to the two formats we parse.

    Anything that is not JSON reads as YAML — the fallback `parse_doc` already
    applied to an unrecognised format, stated once here instead of hiding behind a
    `str` parameter that promised more values than the parser handles.
    """
    return "JSON" if reported.upper() == "JSON" else "YAML"


def parse_doc(content: str, document_format: DocumentFormat) -> Any:
    return json.loads(content) if document_format == "JSON" else yaml.safe_load(content)


def truncate(value: Any, max_chars: int = 300) -> Any:
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return f"{value[:max_chars]}… (truncated)" if len(value) > max_chars else value
    try:
        s = json.dumps(value)
        return f"{s[:max_chars]}… (truncated)" if len(s) > max_chars else json.loads(s)
    except (TypeError, ValueError):
        return "(unserialisable)"


def diff(
    local: Any, remote: Any, path: str = "", entries: list[DiffEntry] | None = None
) -> list[DiffEntry]:
    if entries is None:
        entries = []
    if local == remote:
        return entries

    if isinstance(local, dict) and isinstance(remote, dict):
        for key in dict.fromkeys([*local.keys(), *remote.keys()]):
            next_path = f"{path}.{key}" if path else key
            if key not in local:
                entries.append(
                    {
                        "path": next_path,
                        "changeType": "removed",
                        "local": None,
                        "remote": truncate(remote[key]),
                    }
                )
            elif key not in remote:
                entries.append(
                    {
                        "path": next_path,
                        "changeType": "added",
                        "local": truncate(local[key]),
                        "remote": None,
                    }
                )
            else:
                diff(local[key], remote[key], next_path, entries)
        return entries

    if isinstance(local, list) and isinstance(remote, list):
        for i in range(max(len(local), len(remote))):
            next_path = f"{path}[{i}]"
            if i >= len(local):
                entries.append(
                    {
                        "path": next_path,
                        "changeType": "removed",
                        "local": None,
                        "remote": truncate(remote[i]),
                    }
                )
            elif i >= len(remote):
                entries.append(
                    {
                        "path": next_path,
                        "changeType": "added",
                        "local": truncate(local[i]),
                        "remote": None,
                    }
                )
            else:
                diff(local[i], remote[i], next_path, entries)
        return entries

    entries.append(
        {
            "path": path or "(root)",
            "changeType": "changed",
            "local": truncate(local),
            "remote": truncate(remote),
        }
    )
    return entries


def check(
    document_name: str,
    local_content: str,
    local_format: DocumentFormat,
    region: str | None,
) -> DriftReport:
    ssm = boto3.client("ssm", region_name=region) if region else boto3.client("ssm")
    base: ReportIdentity = {
        "documentName": document_name,
        "localFormat": local_format,
        # Echoed so a wrong-region `missing-remote` is diagnosable.
        "region": ssm.meta.region_name,
    }

    try:
        describe = ssm.describe_document(Name=document_name)
        doc = ssm.get_document(Name=document_name, DocumentFormat=local_format)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code in (
            "InvalidDocument",
            "InvalidDocumentVersion",
        ) or "does not exist" in str(err):
            # Empty, and spelled out rather than omitted: `mypy` will only accept a
            # `**`-built TypedDict if every optional key appears in some unpacked
            # item's *type*. The report keeps the keys out of the JSON either way.
            no_remote_metadata: RemoteDocumentMetadata = {}
            return {
                **base,
                **no_remote_metadata,
                "inSync": False,
                "reason": "missing-remote",
                "structuralDiff": [],
            }
        raise

    remote_content = doc.get("Content")
    remote_format = doc.get("DocumentFormat", "UNKNOWN")
    meta: RemoteDocumentMetadata = {
        "remoteFormat": remote_format,
        "remoteLatestVersion": describe.get("Document", {}).get("LatestVersion"),
        "remoteStatus": describe.get("Document", {}).get("Status"),
    }

    if not remote_content:
        return {
            **base,
            **meta,
            "inSync": False,
            "reason": "missing-remote",
            "structuralDiff": [],
        }

    if local_content.strip() == remote_content.strip():
        return {
            **base,
            **meta,
            "inSync": True,
            "reason": "identical-text",
            "structuralDiff": [],
        }

    parsed_local = parse_doc(local_content, local_format)
    # The report echoes `remoteFormat` exactly as the API said it; only the parser
    # gets the narrowed value.
    remote_parse_format = (
        local_format
        if remote_format == "UNKNOWN"
        else as_document_format(remote_format)
    )
    parsed_remote = parse_doc(remote_content, remote_parse_format)

    entries = diff(parsed_local, parsed_remote)
    if not entries:
        return {
            **base,
            **meta,
            "inSync": True,
            "reason": "identical-structure",
            "structuralDiff": [],
        }
    return {
        **base,
        **meta,
        "inSync": False,
        "reason": "differs",
        "structuralDiff": entries[:MAX_DIFF_ENTRIES],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="check_runbook_drift.py",
        description="Structural diff between a local runbook and the deployed SSM document.",
    )
    parser.add_argument("document_name")
    parser.add_argument("local_file")
    parser.add_argument(
        "--format",
        dest="document_format",
        default="YAML",
        choices=["YAML", "JSON", "yaml", "json"],
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        help="AWS region to query. Defaults to AWS_REGION / AWS_DEFAULT_REGION.",
    )
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else 2

    # argparse `choices` accepts both cases, so this only upper-cases; it is the
    # same narrowing the remote format gets, spelled once.
    document_format = as_document_format(args.document_format)
    try:
        with open(args.local_file, encoding="utf-8") as fh:
            local_content = fh.read()
    except OSError as err:
        print(
            f"check_runbook_drift: cannot read {args.local_file}: {err}",
            file=sys.stderr,
        )
        return 2

    result = check(args.document_name, local_content, document_format, args.region)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("inSync") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
