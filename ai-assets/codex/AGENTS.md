# ASR remediation authoring — OpenAI Codex CLI

Install the shared skill at `.agents/skills/asr-remediation-authoring`, then read:

- `.agents/skills/asr-remediation-authoring/SKILL.md`
- Custom Runbook workflow:
  `.agents/skills/asr-remediation-authoring/references/authoring-loop.md`
- Built-in workflow:
  `.agents/skills/asr-remediation-authoring/references/builtin-remediation.md`

## Codex tool mapping

- Use repository file tools for source changes.
- For AWS operations, use any configured AWS-capable MCP tool when available.
  Do not assume a server alias or tool name. Use the AWS CLI through the shell
  when no suitable MCP tool is present.
- Run the skill's scripts for deterministic and cleanup-sensitive steps:

  ```bash
  python3 .agents/skills/asr-remediation-authoring/scripts/generate_runbook.py --help
  python3 .agents/skills/asr-remediation-authoring/scripts/validate_runbook.py --help
  python3 .agents/skills/asr-remediation-authoring/scripts/test_runbook.py --help
  python3 .agents/skills/asr-remediation-authoring/scripts/check_runbook_drift.py --help
  python3 .agents/skills/asr-remediation-authoring/scripts/deploy_stack.py --help
  ```

- A deployed ASR MCP server is optional and may use any configured name. If its
  tools are present and used, follow `SKILL.md` → `Optional deployed ASR MCP
  context`. Its absence never blocks the local workflow.

## Required safeguards

- Work only in a verified non-production AWS account.
- Verify the AWS account identity before every write phase.
- Use the host approval flow for AWS mutations. Ask only when the exact action
  or target is not already explicit.
- Use the exact document and role naming contracts from the selected workflow.
- Custom Runbooks must accept `Finding` and `AutomationAssumeRole`; derive the
  resource identifier from `Finding` and give every other parameter a default.
- Never invent account-specific values, resource identifiers, email addresses,
  endpoints, or credentials.
- Read structured response bodies before reporting success. Partial results,
  version conflicts, and asynchronous actions are defined in the shared skill.
