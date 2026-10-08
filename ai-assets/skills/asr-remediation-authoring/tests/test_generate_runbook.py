# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/generate_runbook.py.

Covers the two guarantees that make this worth shipping as code: (1) it produces
files that are themselves valid ASR artifacts, and (2) it is idempotent — a
second run never overwrites hand-edited files.
"""
from __future__ import annotations

from pathlib import Path

import generate_runbook
import pytest
import validate_runbook


def test_generates_three_skeleton_files(tmp_path: Path) -> None:
    # GIVEN an empty workspace / WHEN generating for S3.9 / THEN py+yaml+ts appear.
    result = generate_runbook.generate(
        "S3.9", "Enable S3 versioning", service_name="s3", workspace_root=tmp_path
    )
    assert result["controlId"] == "S3.9"
    assert len(result["created"]) == 3
    assert (tmp_path / "source/remediation_runbooks/S3_9/S3_9.py").exists()
    assert (tmp_path / "source/remediation_runbooks/S3_9/S3_9.yaml").exists()
    assert (tmp_path / "source/playbooks/SC/ssmdocs/SC_S3.9.ts").exists()


def test_custom_mode_suggests_the_runtime_authoring_path(tmp_path: Path) -> None:
    result = generate_runbook.generate(
        "S3.9", "Enable S3 versioning", service_name="s3", workspace_root=tmp_path
    )
    next_steps = "\n".join(result["nextSteps"])

    assert result["mode"] == "custom"
    assert "Create the exact remediation role" in next_steps
    assert "test_runbook.py" in next_steps
    assert "--assume-role <role-arn>" in next_steps
    assert not any("npm run build" in step for step in result["nextSteps"])


def test_builtin_mode_suggests_the_source_build_path(tmp_path: Path) -> None:
    result = generate_runbook.generate(
        "S3.9",
        "Enable S3 versioning",
        service_name="s3",
        workspace_root=tmp_path,
        mode="builtin",
    )

    assert result["mode"] == "builtin"
    assert any("builtin-remediation.md" in step for step in result["nextSteps"])
    assert any("npm run build" in step for step in result["nextSteps"])


def test_builtin_mode_validate_command_carries_the_builtin_mode(tmp_path: Path) -> None:
    """The built-in path must suggest `--mode builtin`, not the bare command.

    `validate_runbook.py` defaults to `custom`, which enforces the Orchestrator's
    two-parameter contract. A built-in is a child document behind a wrapper that has
    already parsed the finding, so it legitimately takes `BucketName`/`TopicArn` and no
    `Finding` — exactly what `[orchestrator-parameters]` rejects. Suggesting the bare
    command sent a built-in author to satisfy a rule that does not apply to them, and the
    only way to satisfy it would have been to declare a parameter the document never gets.
    """
    result = generate_runbook.generate(
        "S3.9",
        "Enable S3 versioning",
        service_name="s3",
        workspace_root=tmp_path,
        mode="builtin",
    )

    validate_steps = [s for s in result["nextSteps"] if "validate_runbook.py" in s]
    assert len(validate_steps) == 1
    assert "--mode builtin" in validate_steps[0]


def test_custom_mode_validate_command_stays_on_the_default_mode(tmp_path: Path) -> None:
    """The Custom Runbook path must NOT pass a mode — custom is the default and the
    contract it enforces is the one a Custom Runbook has to satisfy. Asserted so a fix to
    the built-in command above cannot silently exempt the custom path too."""
    result = generate_runbook.generate(
        "S3.9", "Enable S3 versioning", service_name="s3", workspace_root=tmp_path
    )

    validate_steps = [s for s in result["nextSteps"] if "validate_runbook.py" in s]
    assert len(validate_steps) == 1
    assert "--mode" not in validate_steps[0]


def test_builtin_validate_command_accepts_a_real_builtin_shape(tmp_path: Path) -> None:
    """End-to-end on the claim: the suggested command must actually pass a built-in.

    A shape assertion alone would not catch the mode flag being spelled wrongly, or the
    validator changing which rules `builtin` exempts. This runs the mode the generator
    suggests against a document shaped like the shipped built-ins and requires it valid.
    """
    result = generate_runbook.generate(
        "S3.9",
        "Enable S3 versioning",
        service_name="s3",
        workspace_root=tmp_path,
        mode="builtin",
    )
    suggested_mode: validate_runbook.RunbookMode = (
        "builtin" if "--mode builtin" in "\n".join(result["nextSteps"]) else "custom"
    )

    builtin_child_document = "\n".join(
        [
            'schemaVersion: "0.3"',
            "description: |",
            "  ### Document name - ASR-S3.9",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "parameters:",
            "  AutomationAssumeRole:",
            "    type: String",
            "    description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.",
            "  BucketName:",
            "    type: String",
            "    description: (Required) The bucket to check.",
            "mainSteps:",
            "  - name: VerifyLogging",
            "    action: aws:assertAwsResourceProperty",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Service: s3",
            "      Api: GetBucketLogging",
            '      Bucket: "{{ BucketName }}"',
            '      PropertySelector: "$.LoggingEnabled"',
            "      DesiredValues:",
            '        - "true"',
            "",
        ]
    )

    verdict = validate_runbook.validate(builtin_child_document, mode=suggested_mode)

    assert verdict["valid"], verdict["errors"]
    # And the default mode is what would have rejected it, so the flag is load-bearing.
    assert not validate_runbook.validate(builtin_child_document)["valid"]


def test_generated_yaml_has_valid_schema_scaffold(tmp_path: Path) -> None:
    # The generated YAML is a skeleton (mainSteps: []), so it is not yet a
    # complete runbook — but its schemaVersion/assumeRole/param scaffold must be
    # correct so the author only has to fill in mainSteps.
    generate_runbook.generate(
        "S3.9", "desc", service_name="s3", workspace_root=tmp_path
    )
    content = (tmp_path / "source/remediation_runbooks/S3_9/S3_9.yaml").read_text(
        encoding="utf-8"
    )
    result = validate_runbook.validate(content, strict=True)
    # Scaffold is intentionally incomplete: only the empty-mainSteps and
    # missing-verify findings should remain — never a parameter scaffolding bug.
    scaffold_codes = {
        "[schema-version]",
        "[assume-role]",
        "[automation-role-param]",
        "[orchestrator-parameters]",
    }
    assert not any(
        any(err.startswith(code) for code in scaffold_codes) for err in result["errors"]
    ), f"scaffold emitted a structural error: {result['errors']}"
    assert "  Finding:" in content


def test_builtin_scaffold_does_not_declare_finding(tmp_path: Path) -> None:
    """A built-in remediation is a child document; the wrapper never passes Finding.

    None of the shipped child documents under source/remediation_runbooks declares
    it, and a required parameter the wrapper does not send would fail the call.
    """
    result = generate_runbook.generate(
        "S3.9",
        "Block public access",
        service_name="s3",
        workspace_root=tmp_path,
        mode="builtin",
    )
    yaml_path = next(Path(p) for p in result["created"] if p.endswith(".yaml"))
    content = yaml_path.read_text()

    assert "  Finding:" not in content
    assert "  AutomationAssumeRole:" in content
    report = validate_runbook.validate(content, strict=True, mode="builtin")
    assert not any(
        err.startswith("[orchestrator-parameters]") for err in report["errors"]
    ), report["errors"]


def test_idempotent_second_run_creates_nothing(tmp_path: Path) -> None:
    # GIVEN a first generation / WHEN run again / THEN no files are (re)created.
    generate_runbook.generate(
        "S3.9", "first description", service_name="s3", workspace_root=tmp_path
    )
    second = generate_runbook.generate(
        "S3.9", "SECOND description", service_name="s3", workspace_root=tmp_path
    )
    assert second["created"] == []


def test_idempotent_run_does_not_overwrite_edits(tmp_path: Path) -> None:
    # The critical safety property: a re-run must not clobber author edits.
    generate_runbook.generate(
        "S3.9", "desc", service_name="s3", workspace_root=tmp_path
    )
    py_path = tmp_path / "source/remediation_runbooks/S3_9/S3_9.py"
    py_path.write_text("# HAND EDITED — do not overwrite\n", encoding="utf-8")
    generate_runbook.generate(
        "S3.9", "desc", service_name="s3", workspace_root=tmp_path
    )
    assert py_path.read_text(encoding="utf-8") == "# HAND EDITED — do not overwrite\n"


@pytest.mark.parametrize("bad_id", ["S39", "", "S3", "noseparator"])
def test_invalid_control_id_rejected(tmp_path: Path, bad_id: str) -> None:
    with pytest.raises(ValueError):
        generate_runbook.generate(
            bad_id, "desc", service_name="s3", workspace_root=tmp_path
        )


def _run_cli(*extra_arguments: str) -> int:
    return generate_runbook.main(
        [
            "generate_runbook.py",
            "--control-id",
            "EC2.2",
            "--description",
            "d",
            "--service-name",
            "ec2",
            *extra_arguments,
        ]
    )


def _written_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


GENERATED_YAML = "source/remediation_runbooks/EC2_2/EC2_2.yaml"


def test_cli_writes_into_the_checkout_found_above_the_current_directory(
    solution_checkout: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GIVEN the command runs from a subdirectory of the checkout, with no override
    monkeypatch.delenv("ASR_WORKSPACE_ROOT", raising=False)
    monkeypatch.chdir(solution_checkout / "source")

    # WHEN generating without --workspace-root
    rc = _run_cli()

    # THEN the files land at the checkout root, not in a nested `source/source/`
    assert rc == 0
    assert (solution_checkout / GENERATED_YAML).exists()
    assert not (solution_checkout / "source" / "source").exists()


def test_cli_honours_the_workspace_override(
    solution_checkout: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    monkeypatch.setenv("ASR_WORKSPACE_ROOT", str(solution_checkout))
    monkeypatch.chdir(outside)

    assert _run_cli() == 0
    assert (solution_checkout / GENERATED_YAML).exists()
    assert _written_files(outside) == []


@pytest.mark.parametrize("source_of_directory", ["current directory", "override"])
def test_cli_refuses_a_directory_that_is_not_a_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    source_of_directory: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    if source_of_directory == "override":
        monkeypatch.setenv("ASR_WORKSPACE_ROOT", str(tmp_path))
    else:
        monkeypatch.delenv("ASR_WORKSPACE_ROOT", raising=False)

    rc = _run_cli()

    assert rc == 2
    assert "REFUSED" in capsys.readouterr().err
    assert _written_files(tmp_path) == []


def test_cli_writes_an_explicit_workspace_root_as_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The authoring loop drafts into a scratch directory that is not a checkout;
    # an explicit --workspace-root must keep working there, and beat the override.
    scratch = tmp_path / ".tmp" / "EC2.2"
    monkeypatch.setenv("ASR_WORKSPACE_ROOT", str(tmp_path / "not-a-checkout"))

    assert _run_cli("--workspace-root", str(scratch)) == 0
    assert (scratch / GENERATED_YAML).exists()
