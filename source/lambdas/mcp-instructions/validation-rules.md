# ASR Runbook Validation Rules

This catalog explains every rule ID emitted by
`scripts/validate_runbook.py`, why it is reported, and how to correct the runbook.

Only the local script runs these checks. The deployed ASR MCP's `validate_runbook`
tool executes no validation of its own: it returns this catalog verbatim so the
calling agent can apply the rules itself. A response from that tool is therefore
the rule text, not a verdict — run `validate_runbook.py` for a verdict. Repository
tests keep the local and served copies byte-identical.

The command lines and exit codes below describe the local CLI.

## Reading a report

`validate_runbook.py <runbook.yaml>` prints JSON to stdout:

```json
{ "valid": true, "errors": [], "warnings": [], "schemaVersion": "0.3" }
```

Each entry in `errors` / `warnings` is a single string **prefixed with its rule
ID in square brackets** — `[schema-version] Missing required field: ...`. There
is no separate `rule` field; match on the bracketed prefix.

`valid` is `true` only when `errors` is empty. Exit codes: `0` valid, `1`
findings, `2` usage or unreadable file.

## Severities

Three tiers, and which one a rule gets follows from how certain it can be:

| Tier | Strict (default) | `--lenient` | For rules that |
|------|------------------|-------------|----------------|
| **hard** | error | error | recognise a defect with no counter-example |
| **advisory** | error | warning | are right unless you have a reason |
| **hint** | warning | warning | *infer* a problem and can be wrong |

```bash
python3 scripts/validate_runbook.py my-runbook.yaml            # strict
python3 scripts/validate_runbook.py my-runbook.yaml --lenient  # advisories -> warnings
python3 scripts/validate_runbook.py my-runbook.yaml --mode builtin  # in-repo child document
```

`--lenient` never makes a runbook with a bad `schemaVersion` valid, and it makes
no difference at all to a hint.

A hint cannot fail a run — `valid` tracks `errors` only. That is deliberate rather
than lenient: [`destructive-verb`](#destructive-verb) guesses from an API's name,
and if a guess could gate, the author holding a legitimate `DeleteSomething` would
reach for `--lenient` and silence the certain rules along with the wrong one. So
the tool blocks on what it knows and talks about what it suspects.

| Rule | Severity |
|------|----------|
| [`yaml-parse`](#yaml-parse) | hard |
| [`schema-version`](#schema-version) | hard |
| [`assume-role`](#assume-role) | hard |
| [`automation-role-param`](#automation-role-param) | hard |
| [`orchestrator-parameters`](#orchestrator-parameters) | hard — Custom Runbooks only |
| [`hardcoded-secret`](#hardcoded-secret) | mixed — see the rule |
| [`privilege-escalation`](#privilege-escalation) | hard |
| [`main-steps`](#main-steps) | hard |
| [`insecure-transport`](#insecure-transport) | hard |
| [`verify-step`](#verify-step) | advisory |
| [`dangerous-api`](#dangerous-api) | advisory |
| [`disable-security`](#disable-security) | advisory |
| [`missing-timeout`](#missing-timeout) | advisory |
| [`credential-exposure`](#credential-exposure) | advisory |
| [`discouraged-api`](#discouraged-api) | hint |
| [`destructive-verb`](#destructive-verb) | hint |

## What each rule reads

Three different inputs, and the difference decides what the tool can catch:

- **The parsed document** — the shape rules, and the per-step rules that read
  `inputs.Api`.
- **`aws:executeScript` bodies**, taken from the parsed document so a block scalar
  and the quoted form `ssm:GetDocument` returns are treated alike —
  [`privilege-escalation`](#privilege-escalation).
- **The raw YAML text** — [`hardcoded-secret`](#hardcoded-secret),
  [`credential-exposure`](#credential-exposure),
  [`insecure-transport`](#insecure-transport).

The gap worth knowing: the API rules
([`dangerous-api`](#dangerous-api), [`disable-security`](#disable-security),
[`discouraged-api`](#discouraged-api),
[`destructive-verb`](#destructive-verb)) read `inputs.Api`, so they cover
`aws:executeAwsApi` and `aws:assertAwsResourceProperty` steps and nothing else. A
`boto3` call inside a script body is not matched against them, and that is where
most ASR remediation logic lives — this solution's own handlers call
`delete_login_profile`, `delete_secret`, `remove_permission` and both
`revoke_security_group_*` from script bodies. Passing validation is not evidence
that a handler makes no destructive call — read the handler.

---

## Hard rules

### yaml-parse

The input must be valid YAML that parses to a mapping. If the parse raises, or
the result is `None`, a scalar, or a list, this is the **only** rule reported —
nothing else can be checked, so the report stops here with
`schemaVersion: null`.

Common causes:

- Tab characters instead of spaces for indentation
- Unquoted special characters (`:`, `{`, `}`, `[`, `]`, `#`) in string values
- Missing quotes around `"0.3"` or `"{{ AutomationAssumeRole }}"`
- Malformed multi-line strings (wrong `|` or `>` usage)

Fix: make the YAML syntactically valid and ensure the top level is a mapping,
not a list or scalar.

---

### schema-version

Top-level `schemaVersion` must be exactly the string `"0.3"`. Reported as
"missing" when absent or non-string, "unsupported" when present with any other
value.

Common mistake: `schemaVersion: 0.3` without quotes — YAML parses that as the
float `0.3`, which is not the string `"0.3"`.

Fix: `schemaVersion: "0.3"`

---

### assume-role

Top-level `assumeRole` must be a string containing the substring
`AutomationAssumeRole`, so the document runs under the role passed in as a
parameter rather than a hardcoded one.

Fix: `assumeRole: "{{ AutomationAssumeRole }}"`

---

### automation-role-param

`parameters` must exist and be a mapping, and must contain an
`AutomationAssumeRole` key. Existence only — the rule does not inspect that
parameter's `type`, `description`, or `allowedPattern`.

Fix: add to `parameters`:

```yaml
AutomationAssumeRole:
  type: String
  description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'
```

---

### orchestrator-parameters

**Custom Runbooks only** (`--mode custom`, the default). When the ASR
Orchestrator starts a Custom Runbook, the parameters it can rely on receiving are
these two — see `Orchestrator/exec_ssm_doc.py`:

```python
ssm_parameters = {
    "Finding": [json.dumps(event["Finding"])],
    "AutomationAssumeRole": [remediation_role_arn],
}
```

The same function can add more, and none of them reach a Custom Runbook: the six
allow-listed `docParameters` (`Action`, `BackupS3KeyName`, `Rollback`,
`ExecutionId`, `RemediationConfigBucket`, `SnapshotVersionId`) are sent only for a
rollback, which the API refuses for any control outside the built-in
rollback-eligible set; and `RemediationDoc` plus `Workflow` are sent only when an
alternate workflow document is configured, in which case that document is started
in place of yours and receives them. What is unconditional is also what is
guaranteed, so the rule requires both halves of that contract:

1. `parameters.Finding` must exist. Nothing else supplies a bucket name, topic
   ARN or cluster id.
2. Every other parameter must have a `default`. A required parameter the
   Orchestrator never sends fails the execution before the first step runs, with
   `InvalidAutomationExecutionParametersException: Missing required parameter:
   <Name> in user inputs.`

Fix — take `Finding` and derive the identifier in the first step:

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
        Finding: "{{ Finding }}"
      Script: |-
        def parse_finding(event, _context):
            resource_id = event["Finding"]["Resources"][0]["Id"]
            return {"BucketName": resource_id.split(":::")[-1].split("/")[0]}
    outputs:
      - Name: BucketName
        Selector: $.Payload.BucketName
        Type: String
```

`Finding` may be declared `StringMap` (the script receives a dict, as the deployed
built-in `ASR-SC_2.0.0_S3.2` does) or `String` (the script must `json.loads` it).
Both work — the Orchestrator sends `json.dumps(...)` either way — and the rule
checks existence, not `type`.

**Why a mode and not a severity.** A built-in remediation is a *child* document
invoked behind a wrapper that has already parsed the finding, which is why the
built-ins legitimately take `BucketName`/`TopicArn`. For those the rule does not
apply at all, rather than applying more quietly: `--lenient` would also downgrade
unrelated advisories, and a built-in author would be reading a warning about a
contract that is not theirs. Pass `--mode builtin` to exempt it.

**Shape only**, in the same sense as `[automation-role-param]`: this cannot prove
the runbook *reads* `Finding`, only that an execution carrying nothing but the
Orchestrator's two parameters would start. A runbook that declares `Finding` and
then ignores it still fails at run time, just not here.

Apply this rule before deployment and test with the same `Finding` shape the
Orchestrator supplies.

---

### hardcoded-secret

Scans the **raw YAML text** (not the parsed document, so comments and script
bodies are covered too) for three things. The severities differ:

| What it matches | Severity |
|-----------------|----------|
| A bare 12-digit number — probable AWS account ID | advisory |
| An access key ID — `AKIA`/`ASIA` followed by 16 uppercase alphanumerics | error (always) |
| A secret-ish key *assigned a literal value* — see below | error (always) |

The account-ID check is advisory precisely because `\b\d{12}\b` also matches any
other 12-digit number (a timestamp in milliseconds, a large port range, a
retention value). If yours is a false positive, `--lenient` is the escape hatch;
do not work around it by splitting the digits.

The third check requires an **assignment**, not just the identifier: one of
`aws_secret_access_key`, `secret_access_key`, `password`, or `passwd` (case
insensitive, any prefix or suffix — `MasterUserPassword`, `db_password`) followed
by `:` or `=` and a value, quoted or not — `MasterUserPassword: hunter2` and
`password=hunter2` count as much as the quoted forms. Matching the bare identifier would reject
runbooks that legitimately *name* one, e.g. `ASR-ReplaceCodeBuildClearTextCredentials`,
whose whole job is finding `AWS_SECRET_ACCESS_KEY` in a project's environment.

Because any key ending in "password" matches, the **value** decides. These are
exempt, since none can be a literal credential:

- a template reference — `{{ SomeParameter }}`
- a boolean, `null`/`none`, or a plain number
- the empty string, which is also what a key that only *opens* something reads as:
  the value has to be on the same line as the key, so a `Password:` followed by
  `type: String` on the next line declares a parameter rather than assigning one
- an *unquoted* value that reads the secret from somewhere rather than spelling it
  out: `password=$DB_PASS`, `password = os.environ["DB_PASS"]`,
  `MasterUserPassword=event["Password"]`. Inside quotes the same characters are
  part of a literal, so `password: "$DB_PASS"` is still a finding.

That exemption is what keeps a password-*policy* runbook authorable:
`AllowUsersToChangePassword: "True"` and `MinimumPasswordLength: "14"` are
configuration. This matters more than usual here — the rule is an error in both
modes, so `--lenient` is not an escape hatch for it.

Fix: move account IDs to input parameters. Never embed credentials — read them
from SSM Parameter Store or Secrets Manager at run time.

---

### privilege-escalation

Reads every `aws:executeScript` body off the **parsed** document —
`mainSteps[*].inputs.Script` — and fails if either appears inside:

- a wildcard that is the value of an `Action` or `NotAction` key: `"Action": "*"`,
  `"Action": "*:*"`, or a list containing one, e.g. `"Action": ["s3:GetObject", "*"]`
  — **unless the enclosing statement is `"Effect": "Deny"`**, which restricts
  privilege rather than granting it
- `AdministratorAccess`, bare or as the managed-policy ARN in any partition —
  `arn:aws:`, `arn:aws-us-gov:` and `arn:aws-cn:` all match, since ASR is
  supported in all three

Reading the parsed document, not the raw text, is deliberate. Hand-written
runbooks write the body as a block scalar (`Script: |`), but `ssm:GetDocument`
returns the *same* body as a double-quoted scalar with escaped `\n`. YAML
normalizes both to one string, so any rule keyed on `Script:\s*\|` would see zero
script blocks in a document fetched back from AWS — silently skipping the rule on
exactly the drift and verify paths where it matters.

Requiring the wildcard to be an `Action` value is equally deliberate. A bare
`"*"` is legitimate elsewhere in a policy: `"Principal": "*"` is *required* by a
TLS-only bucket-deny policy, and `"Resource": "*"` is often unavoidable. Scanning
for any quoted `*` rejects several shipped ASR runbooks that do the right thing.

The `Deny` carve-out is scoped to the **enclosing statement**, found by walking
braces outward from the matched `Action` — not to the whole script. A policy that
opens with a legitimate deny-all statement and then appends `"Effect": "Allow",
"Action": "*"` still trips the rule. If the braces are unbalanced (so the
statement cannot be isolated) the rule fails closed and flags the wildcard.

Also note: only script bodies are scanned, so the word "administrator" in a
description is not a finding.

Fix: enumerate the specific actions the runbook needs. See
`remediation-iam.md` for deriving them from your steps.

---

### main-steps

Top-level `mainSteps` must be a non-empty list. When this trips, the per-step
rules ([`verify-step`](#verify-step), [`dangerous-api`](#dangerous-api),
[`disable-security`](#disable-security), [`discouraged-api`](#discouraged-api),
[`destructive-verb`](#destructive-verb),
[`missing-timeout`](#missing-timeout)) are skipped — there is nothing to walk.

Fix: ensure `mainSteps` is present with at least one step, each having `name`,
`action`, and `inputs`.

---

### insecure-transport

Fails if the YAML disables TLS verification anywhere. Matched patterns:

- The AWS CLI's SSL-verification-disabling flag
- `PYTHONHTTPSVERIFY = 0`
- `NODE_TLS_REJECT_UNAUTHORIZED = 0`
- `curl` invoked with `-k`

(The CLI flag is described rather than quoted here for the same reason
`validate_runbook.py` assembles it from two fragments: spelled out literally it
trips repo secret/config scanners on this file.)

Fix: use HTTPS with certificate validation. A remediation that needs to reach an
endpoint with an untrusted certificate is a finding, not a fix.

---

## Advisory and hint rules

Advisories are errors by default and `warnings` under `--lenient`. The two hints —
[`discouraged-api`](#discouraged-api) and
[`destructive-verb`](#destructive-verb) — are warnings in both modes. Each rule
below names its tier.

### verify-step

At least one step in `mainSteps` must either use
`action: aws:assertAwsResourceProperty` or have `verify` (case-insensitive)
somewhere in its `name`. This is what stops a runbook from reporting success
without confirming the resource actually changed.

Fix — option A (preferred), assert the property directly:

```yaml
- name: VerifyRemediation
  action: aws:assertAwsResourceProperty
  timeoutSeconds: 600
  isEnd: true
  inputs:
    Service: <service>
    Api: <DescribeOrGetApi>
    <identifier>: "{{ value }}"
    PropertySelector: <JSONPath to changed property>
    DesiredValues:
      - "<expected value>"
```

Fix — option B: an `aws:executeScript` step whose `name` contains "verify"
(`VerifyEncryption`, `verifyConfig`) and which raises on failure.

---

### dangerous-api

Trips when a step's `inputs.Api` is one of `DeleteBucket`,
`TerminateInstances`, `DeleteStack`, `DeleteTable`. The message names the
offending step.

These are irreversible. Fix: prefer a non-destructive alternative. If the API is
genuinely required, pre-check the resource state, scope the call to the single
resource named by an input parameter, and verify the outcome afterwards.

The list is matched exactly, because the object decides whether a call destroys
something — not the verb. `DeleteBucket` destroys a resource; `DeleteBucketPolicy`
removes bad configuration. Exact matching is what earns this rule the right to
block. The general form of the question is
[`destructive-verb`](#destructive-verb), at a severity that suits a guess.

---

### disable-security

Trips when a step's `inputs.Api` is one of `DisableEncryption`,
`SuspendLogging`, `DeleteTrail`, `StopLogging`, `DisableKey`, `DeleteAlarm`,
`DisableAlarmActions`, `DeletePolicy`.

A remediation that switches off a security control is a regression, however the
finding is worded. Fix: re-read the control's intent — the fix is almost always
to *enable* something.

The list is curated to APIs that are indefensible in any remediation, because the
message says "prohibited". `RemovePermission` is not one of them: a resource
policy only ever grants, so removing a statement revokes access instead of
disabling a control, which is precisely what the Lambda.1 remediation does.

---

### discouraged-api

Trips when a step's `inputs.Api` is `PutBucketAcl`. Bucket access belongs in a
bucket policy plus Block Public Access; ACLs are disabled by default on new
buckets. Granting the S3 `LogDelivery` group write access to a logging bucket is
the accepted exception — the shipped CloudTrail logging-bucket remediation needs
it — so this is a separate rule rather than an entry in
[`disable-security`](#disable-security), whose message would call it prohibited.

Fix: express the access change as a bucket policy statement. If you are on the
log-delivery path, this is a hint and does not block you.

---

### destructive-verb

Trips when a step's `inputs.Api` starts with `Delete`, `Terminate`, `Disable`,
`Suspend`, `Stop`, `Remove`, `Revoke`, `Detach` or `Deregister` **and** the API is
not already named by one of the three lists above, and not on the exemption list
in `validate_runbook.py` (`LEGITIMATE_DESTRUCTIVE_APIS`).

This is the general rule the curated lists cannot be. A list only catches what
somebody thought to add, so a novel `DeleteSomething` sails past
[`dangerous-api`](#dangerous-api) untouched. The verb catches the category.

It is a **hint**, and it is worth understanding why, because the honest answer is
that the rule is often wrong. Across the 44 distinct `inputs.Api` values in this
solution's shipped remediation runbooks, the pattern matches three:

| API | Runbook | Why it is correct |
|-----|---------|-------------------|
| `DeleteDBSnapshot` | `EncryptRDSSnapshot` | delete the unencrypted original after re-encrypting |
| `DeleteDBClusterSnapshot` | `EncryptRDSSnapshot` | the cluster-snapshot variant |
| `DeleteLaunchConfiguration` | the two `ConfigureAutoScalingLaunchConfig*` runbooks | replace with a compliant copy, then remove |

All three are right as written, so a gate built on this pattern would refuse to
validate remediations this solution ships. Roughly one API in fifteen is a false
positive — useful as a prompt to justify the call, unacceptable as a gate. Hence
the tier, and hence the exemption list carrying a one-line reason per entry.

Fix, if the finding is fair: redesign so the remediation does not take the
resource away. If deleting *is* the remediation, nothing to fix — say so in the
step name or the description, and add the API to `LEGITIMATE_DESTRUCTIVE_APIS`
with its reason if it is going to recur. Exemption silences this hint only; it is
not a way past [`dangerous-api`](#dangerous-api).

---

### missing-timeout

Trips on any step with `action: aws:executeScript` and no `timeoutSeconds`. A
script step without a timeout can hang an execution indefinitely.

Fix: `timeoutSeconds: 600` on every step — ASR convention, not just script
steps.

---

### credential-exposure

Case-insensitive search of the raw YAML for commands that surface credentials in
plaintext or in process arguments: `net user`, `runas`, `cmdkey`, `useradd`,
`passwd`, `mysql -p`. Reported once, on the first match.

Fix: read credentials from SSM Parameter Store or Secrets Manager inside the
step instead of passing them on a command line.

---

## Conventions not checked by this script

The following ASR requirements are not enforced by
`validate_runbook.py`. Apply them during authoring and review; a valid report does
not prove these conventions are satisfied.

### naming-convention

Three names attach to a runbook: the SSM document name, the remediation role name,
and the title line of the `description` block. Only the title is yours to write in
the YAML, and nothing parses it — it is cosmetic. The document and role names are
not cosmetic: the Orchestrator selects a runbook by them, so a wrong one is never
run. Who assigns them depends on how the runbook is released, and the two paths
use different patterns. Apply the one for your path and do not mix them.

**Released through the `deploy_runbook` MCP tool** (every cloud caller). The
service assigns the document and role names itself, records them with the
runbook, and the Orchestrator resolves them from that record. You choose neither;
the served `generation-instructions.md` shows the patterns it uses, marked by a
`Custom` segment that only this service may issue. Title the description
`ASR-Custom-{ControlId}`, as that guide's examples do.

**Created by hand in your own account** (this skill's loop, `CreateDocument` plus
an IAM role you own). Nothing records anything: the Orchestrator derives both
names from the finding and looks them up verbatim, so these are hard requirements
and a name it cannot derive is unreachable:

| Artifact | Pattern | Example |
|----------|---------|---------|
| SSM Document | `ASR-{shortname}_{version}_{controlId}` | `ASR-SC_2.0.0_SNS.1` |
| Remediation Role | `{solutionId}-Remediate-{shortname}-{version}-{controlId}` | `SO0111-Remediate-SC-2.0.0-SNS.1` |
| Description title | `ASR-{ControlId}` | `ASR-SNS.1` |

No `Custom` segment here: the derivation never produces one, so a hand-created
document carrying it deploys fine and is never selected.

On both paths `{ControlId}` is `ServiceName.Suffix` — `SNS.1`, `S3.4`, and also
alphanumeric suffixes such as `GuardDuty.IAMUser`, matching the control-id pattern
the data models enforce. Do not write a shortname or version into the title; they
belong to the document name, which is assembled at deploy time. Shipped built-in
runbooks are the exception to every title form above: they title themselves after
the remediation — `ASR-EnableMultiAZOnRDSInstance` — because one remediation can
serve several controls. They are the YAML documents under
`source/remediation_runbooks/`, each named for its remediation.

### iam-action-wildcard

The IAM actions declared for the remediation role at deploy time must be
specific — `s3:PutBucketEncryption`, never `s3:*` or `*:*`. Distinct from
[`privilege-escalation`](#privilege-escalation), which only sees wildcards
written inside a `Script:` block; the deploy-time action list is not part of the
runbook YAML, so no local rule can reach it.

### iam-action-prohibited

Do not declare actions the base policy already grants: `iam:PassRole`,
`sts:AssumeRole`, `ssm:GetParameter`, `ssm:GetParameters`, `ssm:PutParameter`,
`ssm:StartAutomationExecution`, `ssm:GetAutomationExecution`,
`ssm:DescribeAutomationStepExecutions`. Listing them again is redundant and
obscures what the runbook actually needs.

See `remediation-iam.md` for the full derivation procedure
and the per-service gotchas.

### rollback-shape

`validate_runbook.py` has no rollback rules; nothing here is enforced on any
surface. A rollback-capable runbook (see
`generation-instructions.md`, "Rollback-capable
runbooks", for the parameters, the dispatch step, and the snapshot framework)
must, by convention: declare the rollback parameters as optional with empty/SSM
defaults so the remediation path is unchanged when they are absent; route the
rollback path **past** the `RESOLVED` finding-update step, since the Orchestrator
owns finding state on rollback; and capture fail-open (a snapshot failure never
blocks remediation) while restoring fail-closed (version-pinned read, abort on
tamper or drift). `common/snapshot_utils.py` enforces the last point — do not
re-implement it.

Apply these rollback conventions during authoring and review.

---

## Fixing validation failures

1. Read each entry in `errors`.
2. Match the bracketed prefix to a rule above.
3. Apply the documented fix.
4. Re-run `validate_runbook.py` on the corrected YAML.
5. Repeat until `valid` is `true`.
6. Then test it for real — `scripts/test_runbook.py` — before deploying.
   `authoring-loop.md` has the full procedure.

Iterating with `--lenient` is fine, but the runbook must pass **strict** before
it is deployed. Strict is what the release gate runs.
