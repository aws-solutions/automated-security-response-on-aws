# AI-assisted ASR remediation authoring

This directory provides one shared skill for authoring Automated Security
Response on AWS (ASR) remediations and optional adapters for Claude Code, Kiro,
and OpenAI Codex CLI.

The local workflow requires AWS access, but it does not require a deployed ASR
MCP server. Use an AWS-capable MCP server when one is already configured in the
host; otherwise the same workflow uses the AWS CLI. A deployed ASR MCP server is
optional and may use any client-local name.

## Contents

| Path | Purpose |
|---|---|
| `skills/asr-remediation-authoring/` | Shared instructions, references, scripts, and tests |
| `claude-code/` | Claude Code agent and command |
| `kiro/` | Kiro custom-agent definition and prompt |
| `codex/` | Repository instructions for OpenAI Codex CLI |
| `prompts/` | Standalone runbook-generation prompt |

## Requirements

- A checkout of this repository.
- Python 3.11 or newer.
- `boto3` and `PyYAML` for the bundled scripts.
- AWS credentials for a non-production account.
- Either the AWS CLI or an AWS-capable MCP server configured in the AI host.
- Kiro CLI 3.0 or newer when using the Kiro adapter.

Set the AWS profile and Region using your normal credential workflow. Do not
store account IDs, credentials, MCP tokens, or private endpoints in these files.

> ⚠️ **_IMPORTANT — the account guard is a guardrail, not isolation._** The
> bundled `scripts/account_guard.py` check that fronts the resource-creating
> scripts is deliberately minimal: it confirms the active credentials resolve to
> the exact account you named, and scans the caller ARN for a `prod`/`prd`
> substring. It does **not** consult AWS Organizations, require an opt-in marker
> in the account, or consult a denylist, so a production account whose ARN
> happens not to contain `prod`/`prd` will pass. Treat it as a typo-and-wrong-
> account guard, not as proof an account is safe to mutate — run this workflow
> only in an account you have independently confirmed is non-production.

For an isolated Python environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install boto3 PyYAML
```

## Install

Install the shared skill plus the adapter for the host you use. The copy commands
are intentionally simple; there is no setup script. Run every command from the
repository root, so the relative `ai-assets/...` source paths resolve and the
installed skill lands where each host looks for it.

Every host follows the same three steps: **install** the skill (and its adapter),
**invoke** it, and **verify** it was picked up. Only the paths and the invocation
differ.

### Claude Code

Installed skill path: `.claude/skills/asr-remediation-authoring`.

1. Install the shared skill and the Claude Code adapter (agent + slash command):

   ```bash
   mkdir -p .claude/skills .claude/agents .claude/commands
   cp -R ai-assets/skills/asr-remediation-authoring .claude/skills/
   cp ai-assets/claude-code/agents/asr-remediation-author.md .claude/agents/
   cp ai-assets/claude-code/commands/remediation-author.md .claude/commands/
   ```

2. Invoke it, any of these three ways:
   - Run the slash command: `/remediation-author <request>`.
   - Invoke the `asr-remediation-author` agent by name.
   - Ask Claude Code in plain language to use the `asr-remediation-authoring` skill.

3. Verify: the skill appears under `.claude/skills/`, `/remediation-author` is
   offered as a command, and Claude Code lists `asr-remediation-author` when
   asked which subagents are available.
   Claude Code loads these at session start, so restart any session that was
   already running. If they are still missing, re-check that you copied from the
   repository root and that Claude Code was started at the repository root.

### Kiro

Installed skill path: `.kiro/skills/asr-remediation-authoring`.

1. Install the shared skill and the Kiro custom-agent definition (JSON + prompt):

   ```bash
   mkdir -p .kiro/skills .kiro/agents
   cp -R ai-assets/skills/asr-remediation-authoring .kiro/skills/
   cp ai-assets/kiro/agents/asr-remediation-author.json .kiro/agents/
   cp ai-assets/kiro/agents/asr-remediation-author-prompt.md .kiro/agents/
   ```

2. Invoke it — start the custom agent from the repository root:

   ```bash
   kiro-cli chat --agent asr-remediation-author
   ```

   The agent declares the installed skill as
   `skill://.kiro/skills/asr-remediation-authoring/SKILL.md`. That path is resolved
   from the directory `kiro-cli` is started in, so start it at the repository root
   (where `.kiro/` was created above), or the skill will not resolve.

3. Verify: `kiro-cli chat --agent asr-remediation-author` starts without a
   skill-resolution error. The agent does not install or name an MCP server;
   existing workspace MCP configuration remains available through `includeMcpJson`,
   and without it the agent uses the AWS CLI.

### OpenAI Codex CLI

Installed skill path: `.agents/skills/asr-remediation-authoring`.

Codex discovers skills from `.agents/skills` while walking from the current
directory up to the repository root.

1. Install the shared skill:

   ```bash
   mkdir -p .agents/skills
   cp -R ai-assets/skills/asr-remediation-authoring .agents/skills/
   ```

2. Give Codex the repository instructions. If the repository already has a root
   `AGENTS.md`, manually merge `ai-assets/codex/AGENTS.md` into it and do not run
   the copy command below. If no root `AGENTS.md` exists, copy it:

   ```bash
   cp ai-assets/codex/AGENTS.md AGENTS.md
   ```

3. Invoke it — ask Codex to use the skill by name:

   ```bash
   codex 'Use $asr-remediation-authoring to author a Custom Runbook for S3.9'
   ```

4. Verify: run Codex from inside the checkout so the walk from the current
   directory reaches `.agents/skills`. If Codex does not find the skill, confirm
   you are at or below the directory where `.agents/skills` was created.

### Updating

The installed files are copies, so they do not change when you pull new
versions of this repository. To update, remove the installed skill and repeat the
install commands for your host. Removing it first matters: copying over an
existing install keeps files that were deleted from the source. For Claude Code:

```bash
rm -rf .claude/skills/asr-remediation-authoring
```

Then rerun the Claude Code install commands above. For Kiro or Codex, remove
`.kiro/skills/asr-remediation-authoring` or
`.agents/skills/asr-remediation-authoring` instead.

## Optional MCP servers

MCP configuration belongs to the host, not to this package.

- An AWS-capable MCP server may replace AWS CLI calls. The server alias and tool
  names are host configuration; the skill identifies the capability rather than
  assuming a fixed name.
- A deployed ASR MCP server adds managed ASR operations and deployed-state
  context. It is optional. When its tools are used, follow the
  `Optional deployed ASR MCP context` section in `SKILL.md`.
- Keep OAuth client IDs, endpoints, tokens, and account-specific values outside
  the copied skill and adapters.

The repository README documents how to connect supported clients to an ASR MCP
gateway when the solution was deployed with that feature enabled.

## Use

Choose the workflow that matches the destination:

- Custom Runbook for one deployed environment:
  `references/authoring-loop.md`.
- Built-in remediation contributed to the solution source:
  `references/builtin-remediation.md`.

Both workflows use the host's normal approval flow for AWS mutations. The
bundled scripts provide deterministic generation and validation, transient-test
cleanup, structural drift checks, and guarded stack deployment.

### Where the scripts look for the checkout

`generate_runbook.py` writes into, and `deploy_stack.py` deploys from, a checkout
of this repository. Both find it the same way: `ASR_WORKSPACE_ROOT` when set,
otherwise the nearest checkout at or above the current directory (and, for
`deploy_stack.py`, above the script itself). The installed copy of the skill can
therefore live anywhere — inside the checkout as shown above, or in a user-level
skills directory such as `~/.kiro/skills` — as long as commands run from inside
the checkout or `ASR_WORKSPACE_ROOT` names it. A directory that is not a checkout
is refused with a message saying so rather than written into or deployed from.
An explicit `--workspace-root` passed to `generate_runbook.py` is used as given,
so drafting into a scratch directory such as `.tmp/<ControlId>` still works.

## Validate the package

The test suite is offline except for explicitly enabled live-integration tests:

```bash
cd ai-assets/skills/asr-remediation-authoring
python -m pip install pytest moto
python -m pytest -q
```

## Authoring rollback-capable remediations

Some remediations can support **safe remediation rollback**: the same SSM
document, invoked with `Rollback=ROLLBACK`, restores the resource's
pre-remediation state from a snapshot captured before the change. Rollback covers
a curated, eligible set of controls — it is not automatic for every remediation,
and it is appropriate only where reversing is a single-resource, reversible
change (not where it re-exposes the resource, destroys audit data, or is
account-wide).

When you ask the skill to make a remediation rollback-capable, it follows the
conventions in
[`references/generation-instructions.md`](skills/asr-remediation-authoring/references/generation-instructions.md)
("Rollback-capable runbooks"). Rollback also requires deploying the administrator
stack with `EnableRollback=yes` (see the repository README) and applies only to
the built-in eligible set of controls.

