# Custom Runbook authoring loop

This is the step-by-step procedure the `asr-remediation-authoring` skill follows
to take one ASR Custom Runbook from a failed Security Hub finding to a verified
remediation in a non-production AWS environment: read the finding, generate and
validate the runbook, test it, deploy it, execute it through the Orchestrator,
and verify the outcome. Follow it in order when the goal is a runbook deployed
into one existing ASR environment.

For a remediation contributed to the solution source, use
`builtin-remediation.md` instead.

In command examples, replace `<skill-dir>` with the installed skill directory.
The workflow is the same whether AWS operations use an AWS-capable MCP server or
the AWS CLI.

## 0. Pre-flight

1. Use the non-production account and Region named in the request; ask only
   when either value is missing.
2. Call STS `GetCallerIdentity` and verify the returned account ID exactly
   matches that value. Stop on a mismatch or a production-looking ARN.
3. Read `references/remediation-iam.md`.
4. Confirm the control is not already covered by a direct or remapped built-in
   runbook:
   - resolve `/Solutions/SO0111/<Shortname>/<version>/<controlId>/remap`
     (this path takes the document shortname, `SC` for FBP; only the
     `/status` parameter in step 5 uses the Security Hub standard name);
   - use the remapped value when present;
   - check `ASR-<Shortname>_<Version>_<EffectiveControlId>` in SSM.
5. Use the host's normal approval flow for AWS mutations. Ask only when the
   requested action or target is not already explicit.

## 1. Read

- Find a failed, new Security Hub finding for a control without remediation
  coverage.
- Record the finding ID, ASFF resource, account, Region, and
  `ProductFields["RelatedAWSResources:0/name"]` Config rule name.
- Read a similar SSM Automation document or source runbook for its API and
  verification pattern.
- Define the exact compliant state and the AWS API calls needed to reach and
  verify it.

## 2. Create

Generate a workspace without writing into the solution source tree:

```bash
python3 "<skill-dir>/scripts/generate_runbook.py" --control-id <ControlId> --description <text> --workspace-root .tmp/<ControlId> --mode custom
```

The generator creates a repository-shaped scaffold. The Custom Runbook YAML is:

```text
.tmp/<ControlId>/source/remediation_runbooks/<Namespace>_<Number>/<Namespace>_<Number>.yaml
```

Set this path for later commands:

```bash
RUNBOOK=.tmp/<ControlId>/source/remediation_runbooks/<Namespace>_<Number>/<Namespace>_<Number>.yaml
```

The scaffold intentionally contains `mainSteps: []`. Author the remediation and
verification steps using `references/generation-instructions.md`.

Custom Runbook parameter contract:

- Declare `Finding` and `AutomationAssumeRole`.
- Derive the resource identifier from the first ASFF resource in `Finding`.
- Give every additional parameter a default because the Orchestrator does not
  supply arbitrary runbook parameters.
- Do not hardcode account IDs, Regions, ARNs, resource names, credentials, or
  operator-specific values.
- End with a verification step that fails when the resource remains
  non-compliant.

If the runbook contains a Python handler, test its parsing and decision logic
locally with a representative synthetic finding before calling AWS.

## 3. Validate

```bash
python3 "<skill-dir>/scripts/validate_runbook.py" "$RUNBOOK"
```

Strict validation must return `valid: true`. Read both `errors` and `warnings`.
Resolve rule IDs with `references/validation-rules.md`; do not use `--lenient` as
a deployment bypass.

## 4. Test the Python handler

Create the final least-privilege remediation role first, then run:

```bash
python3 "<skill-dir>/scripts/test_runbook.py" --script <handler.py> --assume-role <role-arn> --input-payload '<json>'
```

The command is a live test. It creates a transient SSM Automation document,
executes the handler, polls to a terminal state, and deletes the document when
cleanup is enabled. There is no dry-run or `--skip-execution` option.

Use an idempotent operation or a disposable resource. Check the JSON report:

- exit `0`: execution succeeded and requested cleanup completed;
- exit `1`: execution or cleanup failed;
- exit `2`: invalid input, missing dependency, or AWS request error.

The report includes `documentName`, `executionId`, `status`, `failureMessage`,
`output`, and `cleanedUp`. If `--no-cleanup` is used, the operator owns removal
of the transient document.

For a rollback-capable handler, test both paths:

- remediation captures pre-state and reports whether a versioned snapshot was
  stored;
- rollback restores only from the exact snapshot version and fails closed on
  drift or tampering.

`test_runbook.py` runs only the handler script, not the full runbook YAML, so the
document's `CheckRollback` branch and the verification step are not exercised by
this test. Supply the fields in `--input-payload` directly; the transient test
document has no `{{ global:* }}`, `{{ automation:* }}`, or `{{ssm:...}}` defaults,
so pass `AccountId` and `RemediationConfigBucket` yourself, plus the handler's
resource input — a realistic `Finding` for a Custom Runbook (the handler derives
the resource from its first ASFF resource), or the handler's own field (e.g.
`ResourceArn`) for a built-in — and `Region` if the handler reads it. On the
capture run pass `AutomationExecutionId`; on the rollback run
pass `Rollback=ROLLBACK`, `ExecutionId`, and `SnapshotVersionId`. Omit the fields
you are not using rather than passing `""` — SSM rejects an empty parameter value
(`AutomationParameterValue` has a minimum length of 1).

## 5. Deploy

The manual Custom Runbook path has no registry write. The Orchestrator derives
the SSM document and remediation role names from the finding:

```python
automation_docid = f"ASR-{shortname}_{standard_version}_{remediation_control}"
remediation_role = f"SO0111-Remediate-{shortname}-{standard_version}-{remediation_control}"
```

For example:

```text
ASR-SC_2.0.0_EC2.60
SO0111-Remediate-SC-2.0.0-EC2.60
```

Do not add a `Custom` segment on this manual path. Confirm the standard status
parameter `/Solutions/SO0111/<standard-name>/<version>/status` reads `enabled`,
and repeat the built-in collision check immediately before deployment. The
`<standard-name>` in that path is the Security Hub standard name, not the
document shortname: for Security Hub's Foundational Best Practices it is
`security-control`, while the document above (and the `/remap` parameter in
step 0.4) use `SC`. Substituting `SC` here reads a parameter that does not exist
and looks like a disabled standard.

### 5a. IAM role

Create or update the role from `references/remediation-iam.md`:

- trust `ssm.amazonaws.com` and the account's ASR Orchestrator member role;
- grant only remediation and verification APIs;
- scope resources where the AWS API supports resource-level permissions;
- include required service-linked-role or `iam:PassRole` permissions only when
  the selected API needs them.

Use the same role tested in step 4.

### 5b. SSM document

```bash
aws ssm create-document --name ASR-<Shortname>_<Version>_<ControlId> --document-type Automation --document-format YAML --content file://"$RUNBOOK"
```

Wait for `Status: Active` with `DescribeDocument`. Replace an existing manual
document only when the request identifies that document. An SSM document update
creates a new version but does not automatically make that version the default.

### 5c. Baseline

Read the target resource immediately before execution and save the relevant
compliance properties. This baseline is required to prove the runbook changed
state rather than succeeding as a no-op.

## 6. Execute

Before execution, ensure the user's request identifies the document, finding,
account, Region, and expected change. Ask once only when any of these are unclear.

### Direct execution

Use SSM `StartAutomationExecution` with the remediation role and a realistic
`Finding` payload. Poll `GetAutomationExecution` until `Success`, `Failed`,
`Cancelled`, or `TimedOut`.

Direct execution validates the document but does not prove that the ASR
Orchestrator can resolve its name.

### Orchestrator execution

Read the state-machine ARN from `/Solutions/SO0111/OrchestratorArn`. Start it
with the EventBridge envelope expected by the workflow:

```json
{
  "detail-type": "Security Hub Findings - Custom Action",
  "detail": {
    "actionName": "Remediate with ASR",
    "findings": [ <ASFF finding object> ]
  }
}
```

Pass the finding object, not a JSON string. The finding's `Workflow.Status` must
be `NEW`; use the host approval flow if it must be changed with Security Hub
`BatchUpdateFindings`.

Keep the returned execution ARN and inspect execution history and the SSM
Automation result. Do not interpret a workflow being accepted as remediation
success.

Use supported ASR rollback APIs or MCP tools for rollback. A raw custom-action
name is not a substitute for the rollback eligibility and lifecycle checks.

## 7. Verify

- Re-read the resource and compare it with the baseline and expected compliant
  state.
- Start evaluation of the Config rule recorded in step 1 and read its compliance
  result.
- Re-read the Security Hub finding until `Compliance.Status` is `PASSED` and
  `Workflow.Status` is `RESOLVED`, allowing for service propagation delay.
- Record execution IDs and terminal statuses in the result.

Do not report success from an HTTP status, accepted execution, or green SSM step
alone. The final resource and finding state are the result.

## Drift check

```bash
python3 "<skill-dir>/scripts/check_runbook_drift.py" <document-name> "$RUNBOOK" --region <region>
```

Check the `region`, `inSync`, `reason`, and `structuralDiff` fields. A
`missing-remote` result in the wrong Region is not evidence that the document is
absent.

## Failure handling

When a phase fails:

1. Read the structured error or SSM failure message.
2. Correct the underlying IAM, API, parameter, naming, or verification issue.
3. Re-run strict validation.
4. Re-test the affected behavior.
5. Continue only after the failed phase succeeds.

If the same failure repeats, stop and re-check the selected workflow and IAM
capability instead of adding permissions or retries without evidence.

## Temporary files

Keep generated runbooks, trust policies, and inline policies under one scoped
`.tmp/<ControlId>/` directory. Remove that directory only after the durable
source or deployed document has been verified and any required outputs have been
recorded.
