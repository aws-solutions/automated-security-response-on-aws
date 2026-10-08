# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Check that public AI instructions are portable, accurate, and synchronized."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, NamedTuple

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
AI_ASSETS = REPO_ROOT / "ai-assets"
SKILL_ROOT = AI_ASSETS / "skills" / "asr-remediation-authoring"
MCP_INSTRUCTIONS = REPO_ROOT / "source" / "lambdas" / "mcp-instructions"

IGNORED_DIRECTORIES = {"tests", "__pycache__", ".mypy_cache", "node_modules"}
# Phrases that mark a paragraph as describing what the tooling does NOT do, so an
# otherwise-unsupported instruction inside it is a counter-example, not a claim.
# Deliberately narrow: a bare "not" appears in nearly every technical paragraph
# and would exempt a genuine reintroduction of one of the patterns below.
COUNTER_EXAMPLE_MARKERS = re.compile(
    r"\bnever\b|no `|\bthere (?:is|are) no\b|\bnothing reads\b|\bneither path exists\b"
)

PRIVATE_OR_LEGACY_MARKERS = {
    "internal review URL": r"code\.amazon\.com|amazon\.internal",
    "employee email": r"[A-Za-z0-9._%+-]+@amazon\.com",
    "developer workstation path": r"/Users/|/Volumes/[^\s]*/workplace/|workplace/",
    "internal audience wording": r"leadership|internal builder",
    "dated verification narrative": r"verified live on|live end-to-end run",
    "prototype-only tool result": r"MOCK_NOT_EXECUTED|not-yet-shipped",
    "superseded AWS MCP package": r"awslabs\.aws-api-mcp-server",
    "host-generated AWS MCP tool name": r"mcp_aws_",
    "internal review identifier": r"\bCR-\d{6,}\b",
}


class UnsupportedInstruction(NamedTuple):
    """A claim that may appear only when explicitly rejected."""

    label: str
    pattern: str
    scope: Literal["blocks", "lines"]


UNSUPPORTED_INSTRUCTIONS = (
    UnsupportedInstruction(
        "manual runbook name with a Custom segment",
        r"ASR-Custom-\w*_|SO0111-Remediate-Custom(?!-Test-)",
        "blocks",
    ),
    UnsupportedInstruction(
        "custom-runbook registration table or write",
        r"CustomRunbook|dynamodb registration|dynamodb_PutItem",
        "blocks",
    ),
    UnsupportedInstruction(
        "DynamoDB item created by the local loop",
        r"DynamoDB item",
        "lines",
    ),
    UnsupportedInstruction("unsupported dry-run flag", r"--skip-execution", "blocks"),
    UnsupportedInstruction("removed self-check script", r"self_check", "lines"),
    UnsupportedInstruction(
        "removed shared test role", r"ASR-Authoring-TestRole", "lines"
    ),
    UnsupportedInstruction(
        "executeScript caller-credential inheritance",
        r"calling identity|caller(?:'s)? own permissions|your own identity",
        "blocks",
    ),
    UnsupportedInstruction(
        "invalid description heading placeholders", r"^\s*=== |\s~~\s*$", "lines"
    ),
)


def _public_ai_assets() -> list[Path]:
    return sorted(
        path
        for suffix in ("*.md", "*.json")
        for path in AI_ASSETS.rglob(suffix)
        if not IGNORED_DIRECTORIES.intersection(path.parts)
    )


def _shipped_instruction_files() -> list[Path]:
    return _public_ai_assets() + [REPO_ROOT / "README.md"]


def _offenders(path: Path, instruction: UnsupportedInstruction) -> list[str]:
    compiled = re.compile(instruction.pattern, re.IGNORECASE)
    units = (
        path.read_text().splitlines()
        if instruction.scope == "lines"
        else re.split(r"\n\s*\n", path.read_text())
    )
    offenders: list[str] = []
    for unit in units:
        if not compiled.search(unit):
            continue
        collapsed = " ".join(unit.split()).lower()
        if instruction.scope == "blocks" and COUNTER_EXAMPLE_MARKERS.search(collapsed):
            continue
        offenders.append(collapsed[:180])
    return offenders


@pytest.mark.parametrize(
    "asset", _public_ai_assets(), ids=lambda path: str(path.relative_to(AI_ASSETS))
)
def test_public_ai_assets_contain_no_private_or_legacy_markers(asset: Path) -> None:
    content = asset.read_text()
    found = {
        label: pattern
        for label, pattern in PRIVATE_OR_LEGACY_MARKERS.items()
        if re.search(pattern, content, re.IGNORECASE)
    }
    assert not found, f"{asset} contains customer-inappropriate content: {found}"


@pytest.mark.parametrize(
    "document",
    _shipped_instruction_files(),
    ids=lambda path: path.name,
)
def test_shipped_instructions_do_not_recommend_unsupported_workflows(
    document: Path,
) -> None:
    found = {
        instruction.label: matches
        for instruction in UNSUPPORTED_INSTRUCTIONS
        if (matches := _offenders(document, instruction))
    }
    assert not found, f"{document} contains unsupported instructions: {found}"


def test_ai_assets_has_a_customer_install_guide() -> None:
    readme = (AI_ASSETS / "README.md").read_text()
    required = (
        "### Claude Code",
        "### Kiro",
        "### OpenAI Codex CLI",
        ".claude/skills/asr-remediation-authoring",
        ".kiro/skills/asr-remediation-authoring",
        ".agents/skills/asr-remediation-authoring",
        "## Optional MCP servers",
        "there is no setup script",
    )
    missing = [fragment for fragment in required if fragment not in readme]
    assert not missing, f"ai-assets/README.md is missing: {missing}"


def test_repository_readme_links_to_the_ai_assets_guide() -> None:
    readme = (REPO_ROOT / "README.md").read_text()
    assert "## Authoring remediations with an AI coding agent" in readme
    assert "ai-assets/README.md" in readme


def test_repository_readme_treats_the_mcp_name_as_a_local_alias() -> None:
    readme = (REPO_ROOT / "README.md").read_text()
    assert "client-local alias" in readme
    assert "ASR_MCP_NAME" in readme
    assert "asr-cloud" not in readme


def test_skill_documents_the_current_deployed_mcp_contract() -> None:
    skill = (SKILL_ROOT / "SKILL.md").read_text()
    normalized_skill = " ".join(skill.split())
    required = (
        "## Optional deployed ASR MCP context",
        "local server alias is not part of the contract",
        "deploy_runbook",
        "check_deploy_readiness.namespace",
        "test_remediation_script.automation_assume_role",
        "test_runbook_yaml",
        "runbook_id",
        "required_iam_actions",
        "SO0111-Remediate-Custom-Test-",
        "configId",
        'type: "builtin"',
        "ASR-EnableVPCFlowLogs",
        "filterId",
        "failedControlIds",
        "rejectedControlIds",
        "VERSION_CONFLICT",
        "context.currentVersion",
        "processedCount",
        "unresolvedIds",
        "isRollbackEligible",
        "status: IN_PROGRESS",
        "get_execution_status",
        "takes the `finding_id` (not the ARN)",
        "test_notification",
        "push`, `execute`, and `status",
    )
    missing = [fragment for fragment in required if fragment not in normalized_skill]
    assert not missing, f"SKILL.md is missing current MCP behavior: {missing}"
    advertised = {
        tool["name"]
        for tool in json.loads(
            (REPO_ROOT / "source/lambdas/mcp-server/toolSchema.json").read_text()
        )
    }
    documented = {
        "check_deploy_readiness",
        "delete_notification",
        "deploy_runbook",
        "drift_detection",
        "execute_finding_action",
        "execute_runbook",
        "get_execution_status",
        "get_finding_history",
        "get_runbook",
        "list_runbooks",
        "test_notification",
        "test_remediation_script",
        "test_runbook_yaml",
        "update_controls",
        "update_notification",
    }
    assert documented <= advertised
    for tool_name in documented:
        assert tool_name in skill
    for unavailable in (
        "create_remediation_role",
        "execute_rollback",
        "preview_policy_change",
        "apply_policy_change",
        "source_deploy",
    ):
        assert unavailable not in skill
    assert "DELETE_FAILED" not in skill
    assert "mandatory confirmation" not in skill.lower()


def test_test_runbook_creates_no_iam_role() -> None:
    body = (SKILL_ROOT / "scripts" / "test_runbook.py").read_text()
    for call in ("create_role(", "put_role_policy(", 'client("iam"'):
        assert call not in body, f"test_runbook.py performs an IAM write: {call}"


def test_scripts_do_not_advertise_unsupported_flags_or_provenance() -> None:
    for script in sorted((SKILL_ROOT / "scripts").glob("*.py")):
        body = script.read_text()
        assert "--skip-execution" not in body
        assert "source/mcp" not in body
        assert not re.findall(r"\(git [0-9a-f]{7,40}\)", body)


def test_every_validation_rule_code_is_documented() -> None:
    script = (SKILL_ROOT / "scripts" / "validate_runbook.py").read_text()
    documentation = (SKILL_ROOT / "references" / "validation-rules.md").read_text()
    codes = sorted(set(re.findall(r"[\"']\[([a-z][a-z-]+)\]", script)))
    assert len(codes) >= 14, f"rule-code extraction found only {codes}"
    missing = [
        code
        for code in codes
        if f"### {code}" not in documentation or f"(#{code})" not in documentation
    ]
    assert not missing, f"validation-rules.md is missing: {missing}"


def test_authoring_loop_documents_runtime_contracts() -> None:
    loop = (SKILL_ROOT / "references" / "authoring-loop.md").read_text()
    assert "ASR-{shortname}_{standard_version}_{remediation_control}" in loop
    assert (
        "SO0111-Remediate-{shortname}-{standard_version}-{remediation_control}" in loop
    )
    assert "detail-type" in loop
    assert '"findings"' in loop
    assert "actionName" in loop


def test_served_validation_rules_match_the_skill() -> None:
    canonical = SKILL_ROOT / "references" / "validation-rules.md"
    served = MCP_INSTRUCTIONS / "validation-rules.md"
    assert served.read_text() == canonical.read_text()


def test_served_generation_examples_match_the_skill() -> None:
    canonical = SKILL_ROOT / "references" / "generation-examples.md"
    served = MCP_INSTRUCTIONS / "generation-examples.md"
    assert served.read_text() == canonical.read_text()
    served_guide = (MCP_INSTRUCTIONS / "generation-instructions.md").read_text()
    assert "<!-- include: generation-examples.md -->" in served_guide


def test_served_authoring_guide_has_the_orchestrator_parameter_contract() -> None:
    served = (MCP_INSTRUCTIONS / "generation-instructions.md").read_text()
    assert "parameter contract" in served
    assert "AutomationAssumeRole" in served
    assert '"Finding"' in served
    assert "MUST have a `default`" in served
    assert "Orchestrator discovers it" not in served


def test_generation_examples_require_adaptation_for_manual_custom_runbooks() -> None:
    examples = (SKILL_ROOT / "references" / "generation-examples.md").read_text()
    normalized_examples = " ".join(examples.split())
    assert (
        "Adapt direct resource parameters for manual Custom Runbooks"
        in normalized_examples
    )
    assert "derive the identifier from it" in normalized_examples

    for guide in (
        SKILL_ROOT / "references" / "generation-instructions.md",
        MCP_INSTRUCTIONS / "generation-instructions.md",
    ):
        checklist = guide.read_text().split("Validation checklist", 1)[1]
        assert "`Finding` parameter declared" in checklist
