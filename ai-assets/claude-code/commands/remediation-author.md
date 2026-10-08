# ASR remediation author

Use the installed skill for this request:

- `.claude/skills/asr-remediation-authoring/SKILL.md`
- `.claude/skills/asr-remediation-authoring/references/authoring-loop.md` for a
  Custom Runbook.
- `.claude/skills/asr-remediation-authoring/references/builtin-remediation.md`
  for a remediation added to the solution source.

Use any configured AWS-capable MCP tool when available; otherwise use the AWS
CLI. A deployed ASR MCP server is optional, may have any local name, and adds
only the managed operations documented in `SKILL.md`.

Run the bundled scripts for generation, validation, transient testing, drift
checks, and stack deployment. Confirm the non-production account before writes
and use the host approval flow for AWS mutations.

## User request

$ARGUMENTS
