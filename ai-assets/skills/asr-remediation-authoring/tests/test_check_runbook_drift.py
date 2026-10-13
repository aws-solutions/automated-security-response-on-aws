# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/check_runbook_drift.py.

The SSM boundary is simulated with moto (per repo convention: use moto, never
patch boto). We deploy a document, then assert the structural-diff verdict for
identical / drifted / missing-remote cases.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import boto3
import check_runbook_drift
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

REGION = "us-east-1"

RUNBOOK = "\n".join(
    [
        'schemaVersion: "0.3"',
        "description: Drift test document.",
        'assumeRole: "{{ AutomationAssumeRole }}"',
        "parameters:",
        "  AutomationAssumeRole:",
        "    type: String",
        "    description: role",
        "mainSteps:",
        "  - name: Verify",
        "    action: aws:assertAwsResourceProperty",
        "",
    ]
)


def _deploy(content: str, name: str = "ASR-Custom-Drift") -> None:
    ssm = boto3.client("ssm", region_name=REGION)
    ssm.create_document(
        Name=name, DocumentType="Automation", DocumentFormat="YAML", Content=content
    )


# --- pure diff() logic (no AWS) ----------------------------------------------


def test_diff_reports_each_change_type_and_ignores_key_order() -> None:
    """The three verdicts `diff()` can reach on a mapping.

    Key order is the one that has to be right for the tool to be useful at all:
    `GetDocument` does not round-trip YAML key order, so an order-sensitive diff
    would report drift on every document nobody ever edited.
    """
    assert check_runbook_drift.diff({"a": 1, "b": [1, 2]}, {"b": [1, 2], "a": 1}) == []

    changed = check_runbook_drift.diff({"a": 1}, {"a": 2})
    assert changed == [{"path": "a", "changeType": "changed", "local": 1, "remote": 2}]

    keys = check_runbook_drift.diff({"only_local": 1}, {"only_remote": 2})
    assert {e["changeType"] for e in keys} == {"added", "removed"}


def test_diff_paths_point_at_the_element_that_drifted() -> None:
    """`mainSteps` is a list, so per-index paths are what make a report actionable.

    A step added or dropped locally is the most common real drift shape. Reporting
    it as one opaque change to `mainSteps` would leave the reader to re-diff by
    hand, and a nested change has to name the field, not just the step.
    """
    added = check_runbook_drift.diff([1, 2, 3], [1, 2])
    assert [e["changeType"] for e in added] == ["added"]
    assert added[0]["path"] == "[2]"

    removed = check_runbook_drift.diff([1, 2], [1, 2, 3])
    assert [e["changeType"] for e in removed] == ["removed"]
    assert removed[0]["path"] == "[2]"
    nested = check_runbook_drift.diff(
        {"mainSteps": [{"name": "A"}]}, {"mainSteps": [{"name": "B"}]}
    )
    assert nested == [
        {
            "path": "mainSteps[0].name",
            "changeType": "changed",
            "local": "A",
            "remote": "B",
        }
    ]


# --- truncate(): keeps a drift report readable --------------------------------


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ("JSON", "JSON"),
        ("json", "JSON"),
        ("YAML", "YAML"),
        ("yaml", "YAML"),
        # `GetDocument` and argparse provide plain strings. Known JSON values
        # remain JSON; every other value uses the YAML parser.
        ("TEXT", "YAML"),
        ("", "YAML"),
    ],
)
def test_a_reported_format_narrows_to_one_the_parser_handles(
    reported: str, expected: str
) -> None:
    assert check_runbook_drift.as_document_format(reported) == expected


def test_truncate_shortens_only_what_is_too_long_to_read() -> None:
    """One test for a display helper: scalars, strings, containers, and failure.

    The case that earns its place is the last one — a script body can parse to an
    object `json` cannot encode, and the report has to degrade to a marker rather
    than raise in the middle of a diff and lose the findings already collected.
    """
    for value in (None, 1, 1.5, True):
        assert check_runbook_drift.truncate(value) is value

    long_string = check_runbook_drift.truncate("x" * 400)
    assert long_string.endswith("… (truncated)")
    assert len(long_string) < 400

    assert check_runbook_drift.truncate({"a": 1}) == {"a": 1}
    assert check_runbook_drift.truncate(list(range(500))).endswith("… (truncated)")
    assert check_runbook_drift.truncate({1, 2, 3}) == "(unserialisable)"


# --- check() against the moto SSM boundary -----------------------------------


@mock_aws
def test_in_sync_when_identical() -> None:
    _deploy(RUNBOOK)
    result = check_runbook_drift.check("ASR-Custom-Drift", RUNBOOK, "YAML", REGION)
    assert result["inSync"] is True
    assert result["region"] == REGION


@mock_aws
def test_drift_detected_when_structure_differs() -> None:
    _deploy(RUNBOOK)
    edited = RUNBOOK.replace(
        "Drift test document.", "A DIFFERENT description entirely."
    )
    result = check_runbook_drift.check("ASR-Custom-Drift", edited, "YAML", REGION)
    assert result["inSync"] is False
    assert result["reason"] == "differs"
    assert any(e["path"].startswith("description") for e in result["structuralDiff"])


@mock_aws
def test_missing_remote_is_not_in_sync() -> None:
    # No document deployed -> missing-remote, reported (not an exception).
    result = check_runbook_drift.check(
        "ASR-Custom-DoesNotExist", RUNBOOK, "YAML", REGION
    )
    assert result["inSync"] is False
    assert result["reason"] == "missing-remote"


def test_empty_remote_content_is_missing_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A defensive branch: the document exists but GetDocument returned no
    # Content. moto cannot produce that (create_document requires content), so
    # this uses a minimal stand-in for the two calls check() makes — the same
    # documented exception as FakeSsm in test_test_runbook.py.
    class EmptyContentSsm:
        meta = SimpleNamespace(region_name=REGION)

        def describe_document(self, **kwargs: object) -> dict[str, object]:
            return {"Document": {"LatestVersion": "1", "Status": "Active"}}

        def get_document(self, **kwargs: object) -> dict[str, str]:
            return {"Content": "", "DocumentFormat": "YAML"}

    monkeypatch.setattr(boto3, "client", lambda *a, **k: EmptyContentSsm())
    result = check_runbook_drift.check("ASR-Custom-Empty", RUNBOOK, "YAML", REGION)
    assert result["inSync"] is False
    assert result["reason"] == "missing-remote"
    assert result["remoteLatestVersion"] == "1"


def test_identical_structure_is_in_sync_despite_different_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reordered keys and extra blank lines are not drift: the text differs, the
    # parsed structure does not. This is the whole point of a structural diff.
    reordered = "\n".join(
        [
            "description: Drift test document.",
            "",
            'schemaVersion: "0.3"',
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "mainSteps:",
            "  - action: aws:assertAwsResourceProperty",
            "    name: Verify",
            "parameters:",
            "  AutomationAssumeRole:",
            "    description: role",
            "    type: String",
            "",
        ]
    )

    class RemoteSsm:
        meta = SimpleNamespace(region_name=REGION)

        def describe_document(self, **kwargs: object) -> dict[str, object]:
            return {"Document": {"LatestVersion": "3", "Status": "Active"}}

        def get_document(self, **kwargs: object) -> dict[str, str]:
            return {"Content": RUNBOOK, "DocumentFormat": "YAML"}

    monkeypatch.setattr(boto3, "client", lambda *a, **k: RemoteSsm())
    result = check_runbook_drift.check("ASR-Custom-Drift", reordered, "YAML", REGION)
    assert result["inSync"] is True
    assert result["reason"] == "identical-structure"


def test_unexpected_client_error_is_raised_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Only a missing document is a verdict. An AccessDenied must surface, or a
    # permissions problem would silently read as "no drift to worry about".
    class DeniedSsm:
        meta = SimpleNamespace(region_name=REGION)

        def describe_document(self, **kwargs: object) -> dict[str, object]:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "nope"}},
                "DescribeDocument",
            )

    monkeypatch.setattr(boto3, "client", lambda *a, **k: DeniedSsm())
    with pytest.raises(ClientError):
        check_runbook_drift.check("ASR-Custom-Drift", RUNBOOK, "YAML", REGION)


# --- main(): the CLI exit-code contract --------------------------------------
# Called in-process so the assertions cover the real main() branches, and so the
# AWS-touching runs can see the @mock_aws context (a subprocess could not).


def _local_file(tmp_path: Path, content: str = RUNBOOK) -> str:
    f = tmp_path / "local.yaml"
    f.write_text(content, encoding="utf-8")
    return str(f)


@mock_aws
def test_main_exit_zero_when_in_sync(tmp_path: Path) -> None:
    _deploy(RUNBOOK)
    argv = ["prog", "ASR-Custom-Drift", _local_file(tmp_path), "--format", "YAML"]
    assert check_runbook_drift.main(argv) == 0


@mock_aws
def test_main_exit_one_when_drifted(tmp_path: Path) -> None:
    _deploy(RUNBOOK)
    edited = RUNBOOK.replace("Drift test document.", "Something else.")
    argv = ["prog", "ASR-Custom-Drift", _local_file(tmp_path, edited)]
    assert check_runbook_drift.main(argv) == 1


@mock_aws
def test_main_honors_explicit_region_and_reports_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _deploy(RUNBOOK)
    argv = [
        "prog",
        "ASR-Custom-Drift",
        _local_file(tmp_path),
        "--region",
        "us-west-2",
    ]

    assert check_runbook_drift.main(argv) == 1
    assert '"region": "us-west-2"' in capsys.readouterr().out


def test_main_exit_two_on_every_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Three ways to call this wrong, none of which may reach AWS.

    Exit 2 has to be reserved for "you called it wrong", because 0 and 1 are the
    drift verdict — a usage error that exited 1 would read as detected drift.
    """
    assert check_runbook_drift.main(["prog", "only-one-arg"]) == 2
    assert "usage:" in capsys.readouterr().err

    bad_format = ["prog", "ASR-Custom-Drift", _local_file(tmp_path), "--format", "TOML"]
    assert check_runbook_drift.main(bad_format) == 2
    assert "usage:" in capsys.readouterr().err

    unreadable = ["prog", "ASR-Custom-Drift", str(tmp_path / "nope.yaml")]
    assert check_runbook_drift.main(unreadable) == 2
    assert "cannot read" in capsys.readouterr().err
