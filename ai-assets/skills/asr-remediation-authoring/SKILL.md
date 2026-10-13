---
name: asr-remediation-authoring
description:
  Author, validate, test, deploy, and verify Automated Security Response on AWS
  remediations. Use for Custom Runbooks in a non-production AWS environment or
  built-in remediations contributed to the solution source.
---

# ASR remediation authoring

This skill supports two remediation workflows and works with any supported AI
host. Generic AWS operations use an AWS-capable MCP server when one is already
available, with the AWS CLI as a complete fallback. A deployed ASR MCP server is
optional and may use any client-local name.

In command examples, replace `<skill-dir>` with the installed directory that
contains this `SKILL.md` file.

## Choose the workflow

- For a Custom Runbook deployed into an existing ASR environment, read
  `references/authoring-loop.md`.
- For a built-in remediation added to the solution source, read
  `references/builtin-remediation.md`.

Do not combine their naming or deployment rules. A manually deployed Custom
Runbook and a runbook managed by the deployed ASR MCP use different lifecycle
services and may use different generated names.

## Requirements and safety

- Use Python 3.11 or newer with `boto3` and `PyYAML` installed.
- Use AWS credentials scoped to an explicitly identified non-production account.
- Before each AWS write phase, call STS `GetCallerIdentity` and verify the exact
  account ID. A production-looking ARN is an additional stop condition, not the
  sole proof that an account is safe.
- Never store account IDs, credentials, private endpoints, OAuth values, or
  customer-specific data in the skill or adapters.
- Ask for operator-provided values instead of inventing resource identifiers,
  email addresses, thresholds, URLs, or credentials.

## Tool selection

1. Use repository file tools for source changes.
2. For ordinary AWS API calls, use any configured AWS-capable MCP tool. Identify
   it by capability rather than by a fixed server alias or generated tool name.
3. If no suitable MCP tool is available, use the AWS CLI with the same profile
   and Region.
4. Use the bundled scripts for steps that require deterministic validation,
   cleanup, structural comparison, or guarded deployment.
5. Use a deployed ASR MCP tool only when that server is present and the operation
   is useful. The local workflow must continue unchanged when it is absent.

## Bundled scripts

### Generate a scaffold

```bash
python3 "<skill-dir>/scripts/generate_runbook.py"   --control-id <Service.Number>   --description <text>   --workspace-root <directory>   [--mode custom|builtin]
```

The command creates a Python handler, an SSM Automation YAML scaffold, and a
control-runbook TypeScript scaffold without overwriting existing files. The YAML
contains the required `Finding` and `AutomationAssumeRole` parameters and an empty
`mainSteps` array. Author the steps before validation.

`--workspace-root` is written into as given. Without it, the files go into the
solution checkout — `ASR_WORKSPACE_ROOT` when set, otherwise the nearest checkout
at or above the current directory — and a directory that is not a checkout is
refused.

A Custom Runbook receives only `Finding` and `AutomationAssumeRole` from the
Orchestrator. Derive every resource identifier from `Finding`; every additional
parameter must have a default.

### Validate a runbook

```bash
python3 "<skill-dir>/scripts/validate_runbook.py" <runbook.yaml>   [--lenient] [--mode custom|builtin]
```

Use strict mode before deployment. The JSON report contains `valid`, `errors`,
`warnings`, and `schemaVersion`. Resolve every rule using
`references/validation-rules.md`; do not bypass a failed rule.

### Test a Python handler

```bash
python3 "<skill-dir>/scripts/test_runbook.py" --script <handler.py> --assume-role <remediation-role-arn> [--input-payload <json>]
```

This is a live test, not a dry run. It creates a transient SSM document, executes
the handler, polls to a terminal state, and deletes the document when cleanup is
enabled. The role must already exist and grant the handler's required AWS API
actions. The script also accepts `ASR_TEST_ASSUME_ROLE` when `--assume-role` is
not supplied. Region resolution follows `AWS_REGION`, `AWS_DEFAULT_REGION`, and
the standard AWS SDK configuration chain.

### Check drift

```bash
python3 "<skill-dir>/scripts/check_runbook_drift.py" <document-name> <runbook.yaml> [--region <region>]
```

The report compares parsed document structure, so formatting and key order do
not count as drift. Always verify the reported Region; querying the wrong Region
has the same `missing-remote` result as a document that was never deployed.

### Manage non-production stacks

```bash
python3 "<skill-dir>/scripts/deploy_stack.py" --help
```

Use the command help to select an operation. The script can inspect or initialize
an environment, deploy the configured Region, and add a member stack in another
Region. It deploys from a checkout of the solution repository, found as
`ASR_WORKSPACE_ROOT` when set, otherwise the nearest checkout at or above the
current directory; run it from inside the checkout or set that variable.
Writes are refused when the active credentials do not match the
configured account or the caller ARN indicates production. Read
`references/deployment-topology.md` before a multi-Region deployment.

## Manual Custom Runbook contracts

The local Custom Runbook workflow deploys directly with IAM and SSM. Its names
must be derived exactly from the finding:

- SSM document: `ASR-<Shortname>_<Version>_<ControlId>`
- remediation role: `SO0111-Remediate-<Shortname>-<Version>-<ControlId>`

There is no separate registration write. The Orchestrator resolves the document
and role by these names. Do not add a `Custom` segment on this manual path.

Create the remediation role before testing. Trust SSM Automation and the ASR
Orchestrator member role, and grant only the APIs used by the remediation and
verification steps. See `references/remediation-iam.md`.

Before deployment, resolve the control's remap parameter and check the effective
built-in document. A Custom Runbook may fill a coverage gap but must not shadow a
built-in remediation.

## Optional deployed ASR MCP context

The deployed ASR MCP adds managed ASR operations. Its local server alias is not
part of the contract. Apply these rules only when calling its tools:

- Supply `check_deploy_readiness.namespace` and
  `test_remediation_script.automation_assume_role` explicitly.
- `deploy_runbook` uses `action: "register"` to create a DRAFT version and
  `action: "deploy"` to release a registered version. A version must pass a
  recorded `test_runbook_yaml` execution before deployment.
- For a recorded `test_runbook_yaml` execution, supply `runbook_id`, `version`,
  and `required_iam_actions` together. `skip_execution: true` checks only whether
  SSM accepts the document and never records a passing test.
- `test_remediation_script` requires a root-path role in the server's account
  whose name starts with `SO0111-Remediate-Custom-Test-`. It does not read
  `ASR_TEST_ASSUME_ROLE` and does not accept the manual remediation role.
- Both `test_runbook_yaml` and `test_remediation_script` execute the candidate
  YAML/handler **in the ASR administrator account** (the MCP server's own
  account), under a role whose only ceiling is the ASR remediation permissions
  boundary — which denies `sts:*`, `organizations:*`, and `iam:*` but allows any
  other service action the runbook names, run against that account's resources.
  Deploy the ASR MCP server, and run these recorded tests, in a **non-production
  test account** — never an account that is also your production Security Hub
  administrator or holds production workloads. The boundary limits blast radius;
  it is not isolation.
- For `update_notification`, `delete_notification`, and `test_notification`,
  `id` is the `configId` returned by notification create/list operations, not a
  display name.
- `list_runbooks` with `type: "builtin"` returns control runbooks. Shared
  documents such as `ASR-EnableVPCFlowLogs` or `ASR-Orchestrator-*` must be read
  by exact name with `get_runbook`.
- `update_controls` uses `operation: "update"` with versioned control entries in
  `data`, each carrying its current `version` from `list_controls`;
  `applyFilterToAll` and `removeFilterFromAll` take `filterId` (from
  `list_filters`) instead of `data`. A 200 means all entries succeeded, 207
  lists partial failures in `failedControlIds`, and 409 means none succeeded.
  After 207, re-read and retry only the failed controls with current versions —
  except those also listed in `rejectedControlIds`, which are served by a custom
  runbook and are refused on every retry.
- A stale filter or notification update returns 409 with
  `code: "VERSION_CONFLICT"` and `context.currentVersion`. Re-read and reconcile;
  do not blindly retry the stale payload.
- Rollback eligibility comes from the `remediations` tool's `isRollbackEligible`
  on each row, narrowed to the newest row per finding; do not infer eligibility
  from an older success row in `get_finding_history`.
- `execute_runbook` returns the Step Functions execution ARN. Track progress with
  `get_execution_status`, which takes the `finding_id` (not the ARN) and returns
  that finding's recent executions.
- `execute_finding_action` remediation and rollback actions return
  `status: IN_PROGRESS`; poll with `get_execution_status` or
  `get_finding_history` before reporting success. Suppress/unsuppress actions
  complete inline and return `processedCount` and, when some ids could not be
  resolved, `unresolvedIds`.
- `test_notification` verifies channel delivery only. It does not prove that the
  configuration's finding filters match.
- `drift_detection` supports `push`, `execute`, and `status`. Mutating actions
  require the deployment's Custom Runbook development loop to be enabled. Use
  the local drift script when that feature is unavailable.
- Preserve the readable `error`, `code`, and `context` fields returned by tool
  failures.

## Mutation approval

Use the host's normal approval flow for AWS mutations. When the user already
requested the exact action and target, proceed without another conversational
confirmation. Ask once only when either is unclear.

Read structured responses before reporting success. Distinguish a no-op, partial
result, or accepted asynchronous action from a completed change.

## Completion criteria

Before reporting completion:

1. Validation passes in strict mode.
2. Tests cover remediation and verification behavior.
3. The document and role names match the selected workflow.
4. IAM permissions match the actual API calls and resource scope.
5. Any live execution was requested or approved and reached a terminal result.
6. The final AWS state was re-read and verified.
7. Temporary test documents were cleaned up.

## References

- `references/authoring-loop.md` — manual Custom Runbook workflow.
- `references/builtin-remediation.md` — built-in source contribution workflow.
- `references/generation-instructions.md` — runbook content rules.
- `references/generation-examples.md` — step-pattern examples.
- `references/validation-rules.md` — validator rule catalog.
- `references/remediation-iam.md` — remediation-role construction.
- `references/deployment-topology.md` — multi-account and multi-Region stacks.
- `references/ai-generated-metrics.md` — built-in provenance metadata.
