# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verify that each host adapter installs and delegates to the shared skill."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
AI_ASSETS = REPO_ROOT / "ai-assets"
SKILL_ROOT = AI_ASSETS / "skills" / "asr-remediation-authoring"
KIRO_AGENT_JSON = AI_ASSETS / "kiro" / "agents" / "asr-remediation-author.json"

ADAPTER_PROMPTS = {
    "claude": AI_ASSETS / "claude-code" / "agents" / "asr-remediation-author.md",
    "kiro": AI_ASSETS / "kiro" / "agents" / "asr-remediation-author-prompt.md",
    "codex": AI_ASSETS / "codex" / "AGENTS.md",
}

INSTALLED_SKILL_PATHS = {
    "claude": ".claude/skills/asr-remediation-authoring",
    "kiro": ".kiro/skills/asr-remediation-authoring",
    "codex": ".agents/skills/asr-remediation-authoring",
}

BUNDLED_SCRIPTS = (
    "generate_runbook.py",
    "validate_runbook.py",
    "test_runbook.py",
    "check_runbook_drift.py",
    "deploy_stack.py",
)

LEGACY_MCP_MARKERS = (
    "asr-cloud",
    "mcp_aws_",
    "awslabs.aws-api-mcp-server",
)


@pytest.fixture()
def kiro_config() -> dict[str, object]:
    parsed: object = json.loads(KIRO_AGENT_JSON.read_text())
    assert isinstance(parsed, dict)
    assert all(isinstance(key, str) for key in parsed)
    return {key: value for key, value in parsed.items() if isinstance(key, str)}


@pytest.fixture()
def adapter_prompts() -> dict[str, str]:
    for name, path in ADAPTER_PROMPTS.items():
        assert path.is_file(), f"Missing {name} adapter: {path}"
    return {name: path.read_text() for name, path in ADAPTER_PROMPTS.items()}


def _string_list(config: dict[str, object], key: str) -> list[str]:
    value = config.get(key)
    assert isinstance(value, list), f"{key} must be a list"
    assert all(isinstance(item, str) for item in value), f"{key} must contain strings"
    return [item for item in value if isinstance(item, str)]


def test_kiro_agent_uses_current_generic_tool_categories(
    kiro_config: dict[str, object],
) -> None:
    assert _string_list(kiro_config, "tools") == ["read", "write", "shell", "@mcp"]
    assert kiro_config.get("includeMcpJson") is True
    assert "allowedTools" not in kiro_config
    assert "mcpServers" not in kiro_config


def test_kiro_agent_resources_resolve_after_install(
    kiro_config: dict[str, object],
) -> None:
    # `skill://` takes a path to the SKILL.md (relative to the workspace the agent
    # runs in), not a bare skill name; a bare name only appeared to work because
    # Kiro also inherits `.kiro/skills/**/SKILL.md` by default.
    assert _string_list(kiro_config, "resources") == [
        f"skill://{INSTALLED_SKILL_PATHS['kiro']}/SKILL.md"
    ]
    assert (SKILL_ROOT / "SKILL.md").is_file()

    prompt = kiro_config.get("prompt")
    assert isinstance(prompt, str)
    assert prompt.startswith("file://")
    assert (KIRO_AGENT_JSON.parent / prompt.removeprefix("file://")).is_file()


def test_claude_agent_has_valid_frontmatter(
    adapter_prompts: dict[str, str],
) -> None:
    content = adapter_prompts["claude"]
    assert content.startswith("---")
    frontmatter = content[3 : content.index("---", 3)]
    assert "name: asr-remediation-author" in frontmatter
    assert "skills:" in frontmatter
    assert "- asr-remediation-authoring" in frontmatter
    # No `tools:` allowlist on purpose. The agent is told to use whatever
    # AWS-capable and ASR MCP tools the host has configured, and those names are
    # not known in advance — a static list would silently exclude them and force
    # every AWS call through Bash. Least privilege here comes from the account
    # guard and the host's per-call approval flow, not from the tool list.
    assert not any(
        line.strip().startswith(("model:", "tools:"))
        for line in frontmatter.splitlines()
    )


def test_claude_command_delegates_to_the_installed_skill() -> None:
    command = (
        AI_ASSETS / "claude-code" / "commands" / "remediation-author.md"
    ).read_text()
    assert INSTALLED_SKILL_PATHS["claude"] in command
    assert "SKILL.md" in command
    assert "authoring-loop.md" in command
    assert "builtin-remediation.md" in command


def test_codex_adapter_needs_no_generated_setup_files() -> None:
    codex_directory = AI_ASSETS / "codex"
    assert list(codex_directory.glob("*.py")) == []
    assert list(codex_directory.glob("*.toml")) == []


def test_install_guide_covers_all_supported_hosts() -> None:
    readme = (AI_ASSETS / "README.md").read_text()
    for heading in ("### Claude Code", "### Kiro", "### OpenAI Codex CLI"):
        assert heading in readme
    for installed_path in INSTALLED_SKILL_PATHS.values():
        assert installed_path in readme
    assert "there is no setup script" in readme
    assert "may use any client-local name" in readme


@pytest.mark.parametrize("script_name", BUNDLED_SCRIPTS)
def test_bundled_script_help_exits_successfully(script_name: str) -> None:
    result = subprocess.run(
        [sys.executable, str(SKILL_ROOT / "scripts" / script_name), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()


def test_repository_readme_points_to_the_install_guide() -> None:
    readme = (REPO_ROOT / "README.md").read_text()
    assert "## Authoring remediations with an AI coding agent" in readme
    assert "ai-assets/README.md" in readme


def test_every_adapter_uses_its_installed_skill_path(
    adapter_prompts: dict[str, str],
) -> None:
    for name, content in adapter_prompts.items():
        assert INSTALLED_SKILL_PATHS[name] in content
        for pointer in (
            "SKILL.md",
            "authoring-loop.md",
            "builtin-remediation.md",
            *BUNDLED_SCRIPTS,
        ):
            assert pointer in content, f"{name} adapter does not reference {pointer}"


def test_every_adapter_keeps_mcp_optional_and_generic(
    adapter_prompts: dict[str, str],
) -> None:
    for name, content in adapter_prompts.items():
        lowered = content.lower()
        assert "optional" in lowered, f"{name} makes the deployed ASR MCP required"
        assert "aws-capable mcp" in lowered, f"{name} omits generic AWS MCP support"
        assert "aws cli" in lowered, f"{name} omits the AWS CLI fallback"
        for marker in LEGACY_MCP_MARKERS:
            assert marker not in content, f"{name} contains legacy MCP marker {marker}"


def test_every_adapter_carries_the_current_authoring_safeguards(
    adapter_prompts: dict[str, str],
) -> None:
    for name, content in adapter_prompts.items():
        lowered = content.lower()
        assert "non-production" in lowered
        assert "Finding" in content
        assert "AutomationAssumeRole" in content
        assert "approval flow" in lowered
        assert "exact action" in lowered
