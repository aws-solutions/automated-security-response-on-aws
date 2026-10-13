# ASR Custom Runbook Authoring Guide

You are generating an SSM Automation document (runbook) for the Automated
Security Response on AWS (ASR) solution. This runbook will remediate a Security
Hub finding by making AWS API calls to fix the non-compliant resource.

The `generate_runbook` MCP tool returns this document to your IDE. Use the
rules, examples, and guardrails below to produce a valid SSM Automation YAML.
After generation, call `validate_runbook` to get the validation rules and apply
them to the YAML yourself, then `deploy_runbook(action='register')` to store it
as a DRAFT Custom Runbook.

## Built-in runbook boundary

Managed Custom Runbooks are gap-fillers. Do not author one for a control that
ASR already remediates with a built-in runbook. Use
`list_findings_without_runbook` to identify candidate controls before starting.

The deploy service enforces this boundary in every requested member account. It
resolves the control's `/remap` parameter exactly as the Orchestrator does and
then checks the effective `ASR-{standard}_{version}_{control}` document. If any
requested account has that built-in document, the entire deploy is rejected
before an IAM role or SSM Custom Runbook document is created. The deploy
`control_id` must also match the control used when the runbook was registered.

Registration only creates a DRAFT and does not include the standard, version, or
target accounts needed for this check. The definitive block therefore occurs at
deploy time; a DRAFT that conflicts with a built-in can never be released.

## The Orchestrator's parameter contract (read this first)

When the ASR Orchestrator starts a deployed Custom Runbook, the parameters it
will **always** send are these two — see `Orchestrator/exec_ssm_doc.py`:

```python
ssm_parameters = {
    "Finding": [json.dumps(event["Finding"])],
    "AutomationAssumeRole": [remediation_role_arn],
}
```

Consequences the worked examples (`generation-examples.md`) do **not** show, and
which decide whether your runbook runs at all:

1. The runbook MUST declare a `Finding` parameter and derive every resource
   identifier from it. Nothing else supplies a bucket name, topic ARN, or
   cluster id. Declare it `StringMap` (the script receives a dict, as the
   deployed built-in `ASR-SC_2.0.0_S3.2` does) or `String` (the script must
   `json.loads` it) — both work, since the Orchestrator sends `json.dumps(...)`
   either way.
2. Any other parameter MUST have a `default`. A required parameter with no
   default makes the execution fail immediately, because the Orchestrator never
   sends it:
   `InvalidAutomationExecutionParametersException: Missing required parameter: <Name> in user inputs.`
3. A built-in ASR remediation looks different on purpose: it is a _child_
   document invoked behind a wrapper that has already parsed the finding, which
   is why the examples in this guide take `TopicArn` / `BucketName` /
   `LogGroupName`. A Custom Runbook has no wrapper — it IS the document the
   Orchestrator starts.

Parse the resource out of the finding in the first step:

```yaml
parameters:
  Finding:
    type: StringMap
    description: (Required) The ASFF finding, passed by the ASR Orchestrator.
mainSteps:
  - name: ParseFinding
    action: aws:executeScript
    timeoutSeconds: 600
    inputs:
      Runtime: python3.11
      Handler: parse_finding
      InputPayload:
        Finding: '{{ Finding }}'
      Script: |-
        def parse_finding(event, _context):
            resource_id = event["Finding"]["Resources"][0]["Id"]
            # ASFF gives an ARN; most APIs need the bare name.
            return {"BucketName": resource_id.split(":::")[-1].split("/")[0]}
    outputs:
      - Name: BucketName
        Selector: $.Payload.BucketName
        Type: String
```

Later steps then reference `{{ ParseFinding.BucketName }}` rather than a
parameter.

No server-side step enforces this. The `validate_runbook` tool returns the rules
for you to apply — `[orchestrator-parameters]` in them is an error — and it runs
no check of its own; register, `test_runbook_yaml` (you supply the parameters
yourself there) and `deploy_runbook` all accept a runbook that declares resource
parameters instead of `Finding`. It then fails the first time the Orchestrator
invokes it. You are the gate: apply the rule when you read the validation
result, and pass a realistic `Finding` JSON to `test_runbook_yaml`'s
`input_parameters` so the test exercises the same path production will.

## Naming Conventions

Custom Runbooks follow strict naming patterns that match the ASR solution's
conventions:

| Artifact          | Pattern                                                          | Example                       |
| ----------------- | ---------------------------------------------------------------- | ----------------------------- |
| SSM Document      | `ASR-Custom-{standard}_{version}_{controlId}`                    | `ASR-Custom-SC_2.0.0_SNS.1`   |
| Remediation Role  | `{solutionId}-Remediate-Custom-{standard}-{version}-{controlId}` | Managed by ASR deploy service |
| Description title | `ASR-Custom-{ControlId}`                                         | `ASR-Custom-SNS.1`            |

The `{standard}`, `{version}`, and `{controlId}` values are provided at deploy
time — the generated YAML only needs the `{ControlId}` in the description title.

## Required IAM Actions

Every runbook MUST declare the AWS API actions it uses so the deploy step can
provision a least-privilege remediation role in member accounts. When generating
a runbook, identify all AWS API calls in `mainSteps` and list them as
`required_iam_actions` at deploy time.

Rules for IAM actions:

- Use specific action names matching the API calls in the runbook (e.g.,
  `sns:SetTopicAttributes`, `sns:GetTopicAttributes`)
- NEVER use wildcards (`s3:*`, `*:*`)
- Include both remediation AND verification actions
- Include `kms:DescribeKey` and `kms:GenerateDataKey` if the runbook uses KMS
  encryption
- Do NOT include `iam:PassRole`, `sts:AssumeRole`, or `ssm:*` — these are
  handled by the base policy automatically
- Map `aws:executeAwsApi` steps: `Service` + `Api` → IAM action (e.g.,
  `Service: sns, Api: SetTopicAttributes` → `sns:SetTopicAttributes`)
- Map `aws:executeScript` steps: list all `boto3` API calls in the script
- Map `aws:assertAwsResourceProperty` steps: `Service` + `Api` → IAM action
  (e.g., `Service: sns, Api: GetTopicAttributes` → `sns:GetTopicAttributes`)

## Rules

**Schema Requirements**

1. `schemaVersion` MUST be `"0.3"` (quoted string, not a number).
2. `assumeRole` MUST be exactly `"{{ AutomationAssumeRole }}"`.
3. `parameters` MUST include `AutomationAssumeRole` with type String,
   description "(Required) The ARN of the role that allows Automation to perform
   the actions on your behalf.", and allowedPattern
   `'^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'`.
4. Every string parameter MUST have `allowedPattern`. Boolean parameters use
   `allowedValues`.
5. `mainSteps` MUST be a non-empty array.
6. Every step MUST have `name`, `action`, and `inputs`.
7. Every step MUST have `timeoutSeconds: 600`.

**Description Format**

The top-level `description` MUST be a multi-line YAML literal block
(`description: |`) with five sections using markdown headings inside the YAML
block:

- Title heading (h3): Document name - ASR-Custom-{ControlId}
- "What does this document do?" heading (h2) with 1-2 sentences
- "Input Parameters" heading (h2) with bullet list of each parameter
- "Output Parameters" heading (h2) with bullet list of step outputs
- "Security Standards / Controls" heading (h2) with the standard and control ID

See the examples for the exact formatting.

**Parameter Conventions**

- Do NOT declare resource identifiers (ARNs, IDs, names) as parameters. The
  Orchestrator sends only `Finding` and `AutomationAssumeRole` (see "The
  Orchestrator's parameter contract" above), so a resource declared as a
  parameter is never supplied and the execution fails. Derive every resource
  identifier from the `Finding` in the first step instead.
- Every parameter other than `Finding` and `AutomationAssumeRole` MUST have a
  `default` — a required parameter with no default makes the execution fail
  immediately, because the Orchestrator never sends it. This applies to
  behavioral parameters (boolean flags, retention days) as well.
- When a parameter does carry an `allowedPattern`, ARN patterns MUST support all
  three partitions: `aws`, `aws-us-gov`, `aws-cn`.
- Use SSM parameter references (`{{ssm:/Solutions/<solutionId>/...}}`) for
  ASR-managed values like KMS key ARNs.

**Step Actions**

| Action                          | When to use                                                                                   |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| `aws:executeAwsApi`             | Single AWS API call. Preferred for simple operations.                                         |
| `aws:assertAwsResourceProperty` | Verification — assert a resource property matches a desired value.                            |
| `aws:executeScript`             | Complex logic requiring conditionals, loops, or multiple API calls. Use `python3.11` runtime. |

For `aws:executeAwsApi`: `Service` is lowercase (s3, rds, sns), `Api` is
PascalCase (ModifyDBCluster, SetTopicAttributes). Reference parameters with
`"{{ ParamName }}"`.

For `aws:executeScript`: use `Runtime: python3.11`, `Handler: function_name`,
`InputPayload` for parameter mapping, and `Script: |-` for inline Python.
Handler signature: `def function_name(event, context):` returning a dict.

For `aws:assertAwsResourceProperty`: use `PropertySelector` (JSONPath) and
`DesiredValues` (array of expected values) to assert a resource property.

**Step Naming and Flow**

- Use PascalCase: `EnableBucketEncryption`, `VerifyEncryption`.
- Set `isEnd: false` on all steps except the last.
- Set `isEnd: true` on the final step only.
- Use `isCritical: true` on remediation steps that must succeed.
- Use `onFailure: 'Continue'` only for non-critical post-remediation steps
  (e.g., tagging).
- Use `maxAttempts: 3` on steps that may face eventual consistency delays.

**Verification Step (REQUIRED)**

Every runbook MUST include a verification step that confirms the remediation
succeeded:

- Uses `aws:assertAwsResourceProperty` (preferred) or a script that raises on
  failure.
- Queries the resource AFTER the remediation step.
- MUST be the last step with `isEnd: true`.

**Outputs**

- Declare `outputs` at the top level: `- StepName.OutputName`.
- Each step producing output MUST declare `outputs` with `Name`, `Selector`
  (JSONPath), and `Type` (`String`, `StringMap`, `StringList`).

## Examples

<!-- include: generation-examples.md -->

## Guardrails

**Prohibited — NEVER generate these**

- Destructive standalone actions: `DeleteBucket`, `DeleteTable`, `DeleteStack`,
  `TerminateInstances` as the primary remediation. These are irreversible.
- Wildcard IAM: `Resource: "*"` on dangerous actions in any IAM policy
  statement.
- Disabling security: Steps that turn off encryption, logging, access controls,
  or monitoring.
- Hardcoded secrets: AWS account IDs, access keys, secret keys, or passwords in
  the YAML.
- Privilege escalation: Steps that grant `*:*`, `AdministratorAccess`, or overly
  broad IAM permissions.
- Cross-account writes: Steps that modify resources in accounts other than the
  target member account.

**Required safety patterns**

- Pre-check state: Verify the resource exists and is in a modifiable state
  BEFORE making changes (e.g., check RDS cluster status is `available`).
- Post-verify: Always verify the change took effect AFTER the remediation step.
  This is the verification step requirement.
- Scoped operations: API calls MUST target the specific resource identified by
  input parameters — never operate on all resources in an account.
- Retry on consistency: Use `maxAttempts: 3` on steps that may face eventual
  consistency delays.
- Idempotent actions: Prefer API calls that are safe to retry (e.g.,
  `PutBucketEncryption` is idempotent, `CreateBucket` is not).

**Validation checklist**

Before returning the generated YAML, verify every item:

- `schemaVersion: "0.3"` (quoted string)
- `assumeRole: "{{ AutomationAssumeRole }}"` exactly
- `AutomationAssumeRole` parameter with tri-partition `allowedPattern`
- `Finding` parameter declared (the Orchestrator sends only it and
  `AutomationAssumeRole`)
- Every other parameter has a `default`, since nothing else is ever sent
- Every string parameter has `allowedPattern`
- `mainSteps` is non-empty
- Last step has `isEnd: true`
- A verification step exists (`aws:assertAwsResourceProperty` or step name
  containing "verify")
- No prohibited destructive actions
- No hardcoded account IDs or secrets
- `description` follows the required multi-line format (the h3 title and all
  four h2 sub-sections)
- All step outputs declare `Name`, `Selector`, `Type`
- Top-level `outputs` lists all step outputs
- `timeoutSeconds: 600` on every step

**Member Account Role Provisioning**

When a Custom Runbook is deployed, ASR automatically provisions a scoped
remediation role in each specified member account. Understanding this flow helps
you provide the right `required_iam_actions` at deploy time.

Role name pattern:
`{solutionId}-Remediate-Custom-{standard}-{version}-{controlId}` (managed by the
deploy service)

Trust chain (how the role gets created):

1. API Lambda assumes the ASR Orchestrator Admin role (same account)
2. Admin role assumes the ASR Orchestrator Member role (in each member account)
3. Member role creates the remediation role via IAM CreateRole + PutRolePolicy

Trust policy (who can assume the remediation role):

- The ASR Orchestrator Member role in the same member account
- `ssm.amazonaws.com` (SSM Automation service)

The remediation role gets two inline policies:

- **Base policy**: SSM parameter access (ASR solution parameters), PassRole
  (self), StartAutomationExecution
- **Remediation policy**: The `required_iam_actions` you provide at deploy time,
  with `Resource: "*"`

Best practices for `required_iam_actions`:

- Use specific action names: `sns:SetTopicAttributes`, `sns:GetTopicAttributes`
  — not `sns:*`
- Include both the remediation action AND the verification action (e.g., both
  `SetTopicAttributes` and `GetTopicAttributes`)
- Include `kms:DescribeKey` and `kms:GenerateDataKey` if the runbook uses KMS
  encryption
- Do NOT include `iam:*`, `sts:*`, or `ssm:*` — these are handled by the base
  policy
- The Orchestrator Member Role must already be deployed in each member account
  (`automated-security-response-member-roles` stack)

Example for an SNS encryption runbook:

```json
{
  "required_iam_actions": ["sns:SetTopicAttributes", "sns:GetTopicAttributes"],
  "member_account_ids": ["111111111111", "222222222222"]
}
```

**Full end-to-end flow**

This is the complete MCP tool flow from user request to deployed Custom Runbook:

1. User describes the remediation — e.g., "Create a runbook that enables
   encryption on an SNS topic"

2. IDE calls `generate_runbook`:

   ```json
   {
     "description": "Enable encryption on an SNS topic using a KMS key",
     "control_id": "SNS.1"
   }
   ```

3. MCP tool returns context — the tool reads this file from S3 and returns:

   ```json
   {
     "rules": "<content of the Rules section>",
     "examples": "<content of the Examples section>",
     "guardrails": "<content of the Guardrails section>",
     "description": "Enable encryption on an SNS topic using a KMS key"
   }
   ```

   The IDE model uses rules + examples + guardrails + description to generate
   the SSM Automation YAML.

4. IDE calls `validate_runbook`:

   ```json
   { "runbook_yaml": "<generated YAML>" }
   ```

   Returns
   `{ "runbook_yaml": "<...>", "instructions": "<the validation rules>" }`. The
   tool does not check the YAML itself — the IDE model applies those rules to
   the runbook and fixes any violations before registering.

5. IDE calls `deploy_runbook(action='register')`:

   ```json
   {
     "action": "register",
     "runbook_yaml": "<validated YAML>",
     "control_id": "SNS.1"
   }
   ```

   Returns `{ "runbook_id": "a1b2c3d4-...", "version": 1, "status": "DRAFT" }`

6. IDE calls `deploy_runbook(action='deploy')` with role provisioning:
   ```json
   {
     "action": "deploy",
     "runbook_id": "a1b2c3d4-...",
     "control_id": "SNS.1",
     "security_standard": "SC",
     "standard_version": "2.0.0",
     "required_iam_actions": [
       "sns:SetTopicAttributes",
       "sns:GetTopicAttributes"
     ],
     "member_account_ids": ["111111111111", "222222222222"]
   }
   ```
   Returns:
   ```json
   {
     "document_name": "ASR-Custom-SC_2.0.0_SNS.1",
     "document_version": "1",
     "status": "DEPLOYED",
     "remediation_role": "Managed by ASR — scoped to the control ID",
     "role_provisioning": {
       "succeeded": ["111111111111", "222222222222"],
       "failed": []
     }
   }
   ```

The Custom Runbook is now live, and it runs under the provisioned remediation
role in each member account. It is **not** picked up automatically: resolution
matches built-in documents only, and a Custom Runbook is reachable exclusively
through the two manual-trigger event types —
`Security Hub Findings - Custom Action` and `Security Hub Findings - API Action`
(ADR 0012). So it runs from the Security Hub console custom action, the ASR API,
or the MCP `execute_runbook` tool, and never from scheduled or event-driven
ingestion.

What a deploy _does_ change is ingestion: it writes the control's row in the
remediation configuration table, and that row is what makes the synchronization
Lambda store the control's findings at all. Findings imported before the row
existed are not backfilled, so trigger a fresh one when testing a new control.
