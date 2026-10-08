# ASR Custom Runbook Authoring Guide

You are generating an SSM Automation document (runbook) for the Automated Security Response on AWS (ASR) solution. This runbook will remediate a Security Hub finding by making AWS API calls to fix the non-compliant resource.

Use the rules, naming conventions, examples, and guardrails below to produce
valid SSM Automation YAML, then check it with `scripts/validate_runbook.py`. This
file covers **what a correct runbook looks like** and nothing about how it gets
deployed — for the surrounding procedure see
[`authoring-loop.md`](authoring-loop.md).

These conventions apply to both local authoring and managed ASR MCP
workflows. The deployed service bundles the same validation rules and examples so
the runbook requirements remain consistent across hosts.

## Built-in runbook boundary

Custom Runbooks fill coverage gaps; they must not replace a built-in ASR
remediation. Before authoring, resolve the control's `/remap` parameter and
check the effective `ASR-{shortname}_{version}_{controlId}` SSM document in the
target account. If it exists, stop. Choose a control for which ASR has no direct
or remapped built-in runbook.

This is an environment-dependent rule, so the YAML validator cannot prove it.
The managed `deploy_runbook` service performs the check in every requested
member account and rejects the whole release if any collision exists.

## The Orchestrator's parameter contract (read this first)

When the ASR Orchestrator starts a deployed Custom Runbook, the parameters it will
**always** send are these two — see `Orchestrator/exec_ssm_doc.py`:

```python
ssm_parameters = {
    "Finding": [json.dumps(event["Finding"])],
    "AutomationAssumeRole": [remediation_role_arn],
}
```

For a manually deployed Custom Runbook:

1. The runbook MUST declare a `Finding` parameter and derive every resource
   identifier from it. Nothing else supplies a bucket name, topic ARN, or cluster
   id. Declare it `String` (the script must `json.loads` it, as the example below
   does) or `StringMap` (the script receives a dict); the Orchestrator sends
   `json.dumps(...)` either way, and the validator checks that the parameter
   exists, not its type.
2. Any other parameter MUST have a `default`. A required parameter with no default
   makes the execution fail immediately, because the Orchestrator never sends it.
3. A built-in ASR remediation looks different on purpose: it is a *child* document
   invoked behind a wrapper that has already parsed the finding, which is why the
   examples in this guide take `TopicArn` / `BucketName` / `LogGroupName`. A Custom
   Runbook has no wrapper — it IS the document the Orchestrator starts.

Parse the resource out of the finding in the first step:

```yaml
parameters:
  Finding:
    type: String
    description: (Required) The ASFF finding, passed by the ASR Orchestrator as JSON.
    allowedPattern: '^\{[\s\S]*\}$'
mainSteps:
  - name: RemediateResource
    action: 'aws:executeScript'
    timeoutSeconds: 600
    inputs:
      Runtime: python3.11
      Handler: remediate
      InputPayload:
        Finding: '{{ Finding }}'
      Script: |-
        import json

        import boto3


        def remediate(event, _context):
            finding = json.loads(event["Finding"])
            resource_id = finding["Resources"][0]["Id"]
            # ASFF gives an ARN; most APIs need the bare name.
            bucket = resource_id.split(":::")[-1].split("/")[0]
            ...
```

`validate_runbook.py` reports `[orchestrator-parameters]` when this
contract is missing. Do not bypass that error. When testing through an MCP tool,
pass a realistic `Finding` value so the test exercises the production parameter
path.

## Rules

**Schema Requirements**

1. `schemaVersion` MUST be `"0.3"` (quoted string, not a number).
2. `assumeRole` MUST be exactly `"{{ AutomationAssumeRole }}"`.
3. `parameters` MUST include `AutomationAssumeRole` with type String, description "(Required) The ARN of the role that allows Automation to perform the actions on your behalf.", and allowedPattern `'^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'`. It MUST also include `Finding` (type `String` or `StringMap`) — see the parameter contract above; the Orchestrator passes nothing else.
4. Every string parameter MUST have `allowedPattern`. Boolean parameters use `allowedValues`.
5. `mainSteps` MUST be a non-empty array.
6. Every step MUST have `name`, `action`, and `inputs`.
7. Every step MUST have `timeoutSeconds: 600`.

**Description Format**

The top-level `description` MUST be a multi-line YAML literal block (`description: |`) with five sections using markdown headings inside the YAML block:
- Title heading (h3): Document name - ASR-{ControlId}
- "What does this document do?" heading (h2) with 1-2 sentences
- "Input Parameters" heading (h2) with bullet list of each parameter
- "Output Parameters" heading (h2) with bullet list of step outputs
- "Security Standards / Controls" heading (h2) with the standard and control ID

See the examples for the exact formatting.

**Parameter Conventions**

- Do NOT declare resource identifiers (ARNs, IDs, names) as parameters. The Orchestrator sends only `Finding` and `AutomationAssumeRole` (see "The Orchestrator's parameter contract" above), so a resource declared as a parameter is never supplied and the execution fails. Derive every resource identifier from the `Finding` in the first step instead.
- Every parameter other than `Finding` and `AutomationAssumeRole` MUST have a `default` — a required parameter with no default makes the execution fail immediately, because the Orchestrator never sends it. This applies to behavioral parameters (boolean flags, retention days) as well.
- When a parameter does carry an `allowedPattern`, ARN patterns MUST support all three partitions: `aws`, `aws-us-gov`, `aws-cn`.
- Use SSM parameter references (`{{ssm:/Solutions/SO0111/...}}`) for ASR-managed values like KMS key ARNs.

**Step Actions**

| Action | When to use |
|--------|-------------|
| `aws:executeAwsApi` | Single AWS API call. Preferred for simple operations. |
| `aws:assertAwsResourceProperty` | Verification — assert a resource property matches a desired value. |
| `aws:executeScript` | Complex logic requiring conditionals, loops, or multiple API calls. Use `python3.11` runtime. |

For `aws:executeAwsApi`: `Service` is lowercase (s3, rds, sns), `Api` is PascalCase (ModifyDBCluster, SetTopicAttributes). Reference parameters with `"{{ ParamName }}"`.

For `aws:executeScript`: use `Runtime: python3.11`, `Handler: function_name`, `InputPayload` for parameter mapping, and `Script: |-` for inline Python. Handler signature: `def function_name(event, context):` returning a dict.

For `aws:assertAwsResourceProperty`: use `PropertySelector` (JSONPath) and `DesiredValues` (array of expected values) to assert a resource property.

**Step Naming and Flow**

- Use PascalCase: `EnableBucketEncryption`, `VerifyEncryption`.
- Set `isEnd: false` on all steps except the last.
- Set `isEnd: true` on the final step only.
- Use `isCritical: true` on remediation steps that must succeed.
- Use `onFailure: 'Continue'` only for non-critical post-remediation steps (e.g., tagging).
- Use `maxAttempts: 3` on steps that may face eventual consistency delays.

**Verification Step (REQUIRED)**

Every runbook MUST include a verification step that confirms the remediation succeeded:
- Uses `aws:assertAwsResourceProperty` (preferred) or a script that raises on failure.
- Queries the resource AFTER the remediation step.
- MUST be the last step with `isEnd: true`.

**Outputs**

- Declare `outputs` at the top level: `- StepName.OutputName`.
- Each step producing output MUST declare `outputs` with `Name`, `Selector` (JSONPath), and `Type` (`String`, `StringMap`, `StringList`).

## Naming Conventions

A Custom Runbook uses **exactly** the naming the runbooks that ship in the
solution use — there is no separate `Custom` namespace. The Orchestrator derives
both names from the finding and looks them up verbatim
(`source/Orchestrator/resolve_ssm_doc_for_finding.py`), so these are hard
requirements, not conventions:

| Artifact | Pattern | Example |
|----------|---------|---------|
| SSM Document | `ASR-{shortname}_{version}_{controlId}` | `ASR-SC_2.0.0_SNS.1` |
| Remediation Role | `{solutionId}-Remediate-{shortname}-{version}-{controlId}` | `SO0111-Remediate-SC-2.0.0-SNS.1` |
| Description title | `ASR-{ControlId}` | `ASR-SNS.1` (cosmetic — nothing parses it) |

`{solutionId}` is `SO0111` for ASR. `{shortname}` is the standard's abbreviation
(`SC` for Security Hub's Foundational Best Practices), read by the Orchestrator
from `/Solutions/SO0111/{standard-name}/{version}/shortname`.

The document name and role name are supplied at deploy time — **the YAML you
generate only needs the bare `{ControlId}` in its description title.** Writing
the fully-qualified document name into the description is the most common mistake
here.

**There are no registration parameters.** Nothing reads
`/Solutions/SO0111/CustomRunbook/{controlId}` or
`/Solutions/SO0111/Custom/{controlId}/status`; neither path exists. The only gate
outside naming is the standard itself being enabled —
`/Solutions/SO0111/{standard-name}/{version}/status` must equal `enabled`, and
that parameter is created by the solution, not by you.

## Required IAM Actions

A runbook cannot execute until its remediation role grants the AWS API actions
its steps call, so the deploy step needs that action list. Derive it from the
steps rather than guessing:

- `aws:executeAwsApi` — the `Service` + `Api` pair maps directly (`Service: sns`,
  `Api: SetTopicAttributes` → `sns:SetTopicAttributes`)
- `aws:assertAwsResourceProperty` / `aws:waitForAwsResourceProperty` — the
  `describe`/`get` being asserted on (`sns:GetTopicAttributes`)
- `aws:executeScript` — every `boto3` call inside the script body

Rules for the list:

- Specific actions only — never `s3:*` or `*:*`
- Include the **verification** actions as well as the remediation ones; a runbook
  that can fix but not verify fails its last step
- Add `kms:DescribeKey` and `kms:GenerateDataKey` when the runbook encrypts with
  a KMS key
- Omit `iam:PassRole`, `sts:AssumeRole`, and `ssm:*` — the base policy attached
  to every remediation role already grants these

Several SSM Automation actions need IAM beyond the API they wrap
(`aws:runInstances` needs `iam:PassRole`, `aws:runCommand` needs
`ssm:SendCommand`, …). [`remediation-iam.md`](remediation-iam.md) has the full
table, ARN/partition scoping, and the per-service gotchas — read it before
writing the role.

## Examples

Four complete worked runbooks — SNS encryption, RDS Multi-AZ, S3 versioning, and a
CloudWatch retention `executeScript` — live in
[`generation-examples.md`](generation-examples.md). Read them after the
Rules above: they demonstrate step mechanics. Examples with direct resource
parameters must be adapted to the `Finding` contract before use as a manual Custom
Runbook.

## Rollback-capable runbooks

Snapshot-based rollback covers the eligible controls in
`ROLLBACK_ELIGIBLE_FINDING_TYPES`. A rollback-capable remediation is the **same**
SSM document invoked with `Rollback=ROLLBACK` — there are no separate
`ASR-Rollback-*` documents. Add rollback only where reversing is a
single-resource, reversible attribute change
(a flag, one policy statement, an encryption setting). Do **not** add it where
reversing re-exposes the resource to the vulnerability (e.g. removing an S3
public-access block), destroys audit data, or is account-wide and irreversible.

Two documents change; know which one you are editing:

- **Remediation runbook** (`source/remediation_runbooks/<Name>.yaml`, deployed as
  `ASR-<Name>`) holds the snapshot-capture and restore logic in one step.
- **Control runbook** (`source/playbooks/<STD>/ssmdocs/*.ts`, deployed as
  `ASR-<shortname>_<version>_<controlId>`) declares and forwards the rollback
  parameters and adds the `CheckRollback` branch. `ControlRunbookDocument`
  generates this when the control sets `isRollbackEnabled: true` — see
  `builtin-remediation.md`. A run-time **Custom Runbook** has no separate control
  runbook, so put the parameters and the dispatch in the one document you deploy.
  Note the gated one-click rollback (ASR Web UI / MCP `execute_finding_action`)
  only fires for controls in `ROLLBACK_ELIGIBLE_FINDING_TYPES` — a fixed set of
  built-in controls with snapshot rollback (plus the legacy GuardDuty type); a
  custom control is not in that set, so a Custom Runbook's rollback is not
  reachable through the operator one-click surface. It runs only when the
  document is invoked directly with `Rollback=ROLLBACK` (e.g. passed via
  `test_runbook.py --input-payload`), or when the Orchestrator is started with the rollback docParameters while
  `ENABLE_ROLLBACK=yes`. The eligible-set check lives at the API layer
  (`findingsService`); the Orchestrator's own gate
  (`exec_ssm_doc.py` `_validate_rollback_parameters_allowed`) checks only
  `ENABLE_ROLLBACK`, not the control.

**Rollback parameters** — four, all optional with empty or SSM defaults so the
remediation path is unchanged when they are absent:

```yaml
Rollback:
  type: String
  default: ""
  description: "(Optional) Set to ROLLBACK to execute rollback instead of remediation."
  allowedValues: ["", "ROLLBACK"]
ExecutionId:
  type: String
  default: ""
  description: "(Optional) Original SSM Automation execution ID for snapshot lookup during rollback."
  allowedPattern: '^$|^[a-zA-Z0-9-]{1,64}$'
RemediationConfigBucket:
  type: String
  default: "{{ssm:/Solutions/SO0111/RemediationConfigurationBucket}}"
  description: "(Optional) S3 bucket name for snapshot storage."
  allowedPattern: '^$|^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
SnapshotVersionId:
  type: String
  default: ""
  description: "(Optional) S3 version ID of the snapshot object for tamper-proof reads during rollback."
  allowedPattern: '^$|^[A-Za-z0-9+/=._-]{1,1024}$'
```

The remediation runbook also declares `ControlExecutionId` (same String, empty
default, `'^$|^[a-zA-Z0-9-]{1,64}$'`). The control runbook passes
`{{automation:EXECUTION_ID}}` into it, and the script uses it as the S3 snapshot
key on the capture path; `Rollback`, `ExecutionId`, `SnapshotVersionId`, and
`RemediationConfigBucket` are forwarded verbatim.

**One dispatch step, not two.** The remediation runbook is a single
`aws:executeScript` step whose handler branches on `Rollback`:

```yaml
mainSteps:
  - name: SnapshotRemediateOrRollback
    action: aws:executeScript
    timeoutSeconds: 600
    isEnd: true
    inputs:
      Runtime: python3.11
      Handler: handler
      InputPayload:
        <ResourceId>: "{{ <ResourceId> }}"
        AccountId: "{{ global:ACCOUNT_ID }}"
        RemediationConfigBucket: "{{ RemediationConfigBucket }}"
        AutomationExecutionId: "{{ ControlExecutionId }}"
        Rollback: "{{ Rollback }}"
        ExecutionId: "{{ ExecutionId }}"
        SnapshotVersionId: "{{ SnapshotVersionId }}"
      Script: |-
        %%SCRIPT=<Name>_rollback.py%%
    outputs: # every key present on both paths so the selectors always resolve
      - { Name: snapshotStored, Selector: $.Payload.snapshotStored, Type: String }
      - { Name: snapshotVersionId, Selector: $.Payload.snapshotVersionId, Type: String }
      - { Name: rollbackDescription, Selector: $.Payload.rollbackDescription, Type: String }
      - { Name: Message, Selector: $.Payload.Message, Type: String }
      - { Name: Status, Selector: $.Payload.Status, Type: String }
```

The `handler` returns all five output keys on both paths (empty on the path that
did not run) so the selectors resolve either way: the capture path sets
`snapshotStored`, `snapshotVersionId`, `rollbackDescription`; the rollback path
sets `Message`, `Status`.

**Verification still applies to a custom rollback runbook.** The single dispatch
step above is the *built-in remediation-runbook* shape — invoked from a control
runbook via `aws:executeAutomation` and never run through `validate_runbook.py`,
so it carries no `[verify-step]`. A run-time Custom Runbook is the document the
Orchestrator calls directly and is validated strict, so it must still satisfy the
[`verify-step`](validation-rules.md#verify-step) rule. Structure it like the
control runbook: keep the remediation's `aws:assertAwsResourceProperty`
verification on the remediation path, and use a `CheckRollback` branch to route
the rollback path past it to a terminal step. `validate_runbook.py` has no
rollback rules, so a rollback document that drops verification is flagged — that
is the validator working, not a rollback exception.

**Use the shared framework, do not re-implement S3 or drift logic.** In the
handler `.py` script, import from `common/snapshot_utils.py` and add the
`# %%INCLUDE=common/snapshot_utils.py%%` directive there — the build strips the
local import and inlines the module into the script, so the directive lives in
the handler script, not the runbook YAML (the YAML uses
`%%SCRIPT=<Name>_rollback.py%%`). The solution build (`runbook_factory.ts`)
expands `%%INCLUDE` at build time, and `test_runbook.py` expands it too before
building the transient test doc (same logic), so you can test a rollback handler
as-authored with no manual step. A manual `create-document` (deploying outside
the build) still sends the script as written, so inline `snapshot_utils.py` for
that path or the handler fails with
`ModuleNotFoundError: No module named 'common'`. The script's `handler` delegates
to the two framework entry points through `dispatch_rollback_handler(event,
context, capture_fn=…, rollback_fn=…)`, which routes on `Rollback`: `capture_fn`
runs the capture path, `rollback_fn` the rollback path.

- **Capture path — fail-open.** Read the resource's current state; on a read
  error skip the snapshot and still remediate. Call `capture_snapshot(bucket,
  execution_id=…, account_id=…, resource_id=…, control_id=…, pre_state=…,
  post_state=…)` — it wraps `build_snapshot` + `write_snapshot`, stores
  `snapshots/{execution_id}/{control_id}.json`, and returns `(is_stored,
  versionId)` — then remediate. A no-op
  remediation (already compliant) skips the snapshot and returns `snapshotStored:
  "false"`. A snapshot is rollback-able only when it was stored **and** returned a
  non-empty `versionId`; an unversioned bucket returns none and rollback then
  fails closed.
- **Rollback path — fail-closed.** `SnapshotVersionId` is required;
  `read_snapshot(..., version_id=...)` reads that exact version so post-capture
  tampering aborts. `resolve_rollback_action(current, original, post)` returns
  NOOP when `current == original` (an idempotent second rollback — checked
  **before** drift), DRIFT when `current != post` (the resource changed after
  remediation — abort, leave it), else RESTORE to `original`. Failures raise
  `RollbackError`/`RuntimeError` so SSM marks the step Failed, reported as
  `ROLLBACK_FAILED`.

The snapshot envelope is `{schemaVersion: 1, resourceId, controlId, capturedAt,
preRemediationState, postRemediationState}` — both states are stored because the
drift check compares the current resource against `postRemediationState`. A
schema-version mismatch on read is treated as no usable snapshot.

`rollbackDescription` is built at capture time from the observed pre-state (e.g.
`"Disable key rotation for key <id>"`). It carries the exact prior value the Web
UI shows in its confirmation dialog, so it can only be produced at execution time.

**Capture-path invariants — get these wrong and you break the remediation or a
future rollback:**

- **Gate the no-op check on a *successful* pre-state read.** A rollback-capable
  remediation runs as an `aws:executeScript` that reads the resource first to
  snapshot pre-state. That read is **fail-open**: if it fails, still remediate and
  skip the snapshot (this execution just isn't rollback-eligible). **Never** treat
  a failed read as "already compliant" — a transient read error would otherwise
  leave the resource unremediated. Return a `can_capture_snapshot` flag from the
  pre-state read and gate the "no remediation needed" branch on it.
- **Only snapshot when remediation changes state (`original != post`).**
  `resolve_rollback_action` assumes the stored `original` and `post` differ;
  snapshotting a no-op makes NOOP and RESTORE indistinguishable on rollback. A
  no-op remediation writes no snapshot.
- **Confirm the change settled before recording `postRemediationState`.** Many
  AWS mutations are eventually consistent; recording `post` before the change
  materializes makes a later rollback's drift check see a false DRIFT and refuse
  a valid rollback. Wait for and verify the post-state (see the RDS script's
  `_wait_and_verify_state`).
- **Never delete a snapshot on remediation failure.** A snapshot written before a
  remediation that then fails is intentionally orphaned — the Orchestrator won't
  mark it `rollbackAvailable` and the `snapshots/` S3 lifecycle rule reclaims it.
  Deletion logic races the retry path.

**Control-runbook side (built-ins only).** Setting `isRollbackEnabled: true` makes
the base class declare the four parameters, forward them plus
`ControlExecutionId: {{automation:EXECUTION_ID}}` in the `Remediation` step's
`RuntimeParameters`, and insert `CheckRollback` **after** `Remediation`.
`CheckRollback` routes the rollback path past `UpdateFinding` (skipping the
`RESOLVED` write) to the terminal step: the Orchestrator, not the document, owns
finding state on rollback. It is not the first step and must never gate the
remediation path.

**IAM additions** (deploy-time role, per `remediation-iam.md`): add `s3:GetObject`,
`s3:GetObjectVersion`, and `s3:PutObject` on
`arn:<partition>:s3:::so0111-asr-remediation-*-<account>/snapshots/*`, plus
the per-control Describe/Get operation that reads pre-state (e.g.
`kms:GetKeyRotationStatus`). The restore API is already granted — it is the same
call the remediation makes.

## Guardrails

**Prohibited — NEVER generate these**

- Destructive standalone actions: `DeleteBucket`, `DeleteTable`, `DeleteStack`, `TerminateInstances` as the primary remediation. These are irreversible.
- Wildcard IAM: `Resource: "*"` on dangerous actions in any IAM policy statement.
- Disabling security: Steps that turn off encryption, logging, access controls, or monitoring.
- Hardcoded secrets: AWS account IDs, access keys, secret keys, or passwords in the YAML.
- Privilege escalation: Steps that grant `*:*`, `AdministratorAccess`, or overly broad IAM permissions.
- Cross-account writes: Steps that modify resources in accounts other than the target member account.

**Required safety patterns**

- Pre-check state: Verify the resource exists and is in a modifiable state BEFORE making changes (e.g., check RDS cluster status is `available`).
- Post-verify: Always verify the change took effect AFTER the remediation step. This is the verification step requirement.
- Scoped operations: API calls MUST target the specific resource identified by input parameters — never operate on all resources in an account.
- Retry on consistency: Use `maxAttempts: 3` on steps that may face eventual consistency delays.
- Idempotent actions: Prefer API calls that are safe to retry (e.g., `PutBucketEncryption` is idempotent, `CreateBucket` is not).

**Validation checklist**

Before returning the generated YAML, verify every item:

- `schemaVersion: "0.3"` (quoted string)
- `assumeRole: "{{ AutomationAssumeRole }}"` exactly
- `AutomationAssumeRole` parameter with tri-partition `allowedPattern`
- `Finding` parameter declared (the Orchestrator sends only it and `AutomationAssumeRole`)
- Every other parameter has a `default`, since nothing else is ever sent
- Every string parameter has `allowedPattern`
- `mainSteps` is non-empty
- Last step has `isEnd: true`
- A verification step exists (`aws:assertAwsResourceProperty` or step name containing "verify")
- No prohibited destructive actions
- No hardcoded account IDs or secrets
- `description` follows the required multi-line format (one h3 title + four h2 sub-sections)
- All step outputs declare `Name`, `Selector`, `Type`
- Top-level `outputs` lists all step outputs
- `timeoutSeconds: 600` on every step

**After generating**

Generating the YAML is one step of the loop, not the end of it. Validate, test
against a real finding, then deploy — [`authoring-loop.md`](authoring-loop.md)
is the procedure, and it is the same procedure whichever host you are running in.

Registration and deployment differ between the manual workflow and managed ASR
MCP tools. Follow the lifecycle instructions for the selected workflow.
