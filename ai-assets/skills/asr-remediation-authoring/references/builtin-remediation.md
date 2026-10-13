# Built-in remediation workflow

Use this workflow to add a remediation to the ASR solution source so it can be
included in a future solution release. For a Custom Runbook deployed into one
existing ASR environment, use `authoring-loop.md` instead.

In command examples, replace `<skill-dir>` with the installed skill directory.

## Choose the scope

| Scope | Work performed | AWS changes |
|---|---|---|
| `GENERATE` | Implement, build, and run repository checks | None |
| `FULL` | `GENERATE` plus deployment to a confirmed non-production environment | CloudFormation stacks |
| `FULL TEST` | `FULL` plus full tests and live finding verification | Stacks and a test resource |

Use `GENERATE` unless the request explicitly selects a wider scope. For AWS
changes, use the host's normal approval flow.

## Inputs

- `control_id`: Security Hub control identifier such as `S3.9`.
- `playbooks`: target playbooks; include `SC`.
- `scope`: `GENERATE`, `FULL`, or `FULL TEST`.
- expected remediation API, resource identifier shape, and verified compliant
  state.

Do not invent account-specific values or remediation requirements. Ask the
operator when the source and public AWS API contract do not establish them.

## 1. Inspect the source

- Confirm the repository contains `source/` and `deployment/`.
- Read the closest remediation under `source/remediation_runbooks/`.
- Read the corresponding control runbook under
  `source/playbooks/SC/ssmdocs/`.
- Read `source/lib/remediation-runbook-stack.ts` for IAM integration.
- Confirm whether the target API needs a full ARN or an extracted identifier,
  whether the resource is regional or global, and how compliance is verified.

## 2. Generate and implement

Create the scaffold:

```bash
python3 "<skill-dir>/scripts/generate_runbook.py" --control-id <ControlId> --description <text> --workspace-root .tmp/<ControlId> --mode builtin
```

Use `references/generation-instructions.md` and
`references/remediation-iam.md` while implementing the following artifacts.

### Remediation runbook

Create `source/remediation_runbooks/<PascalCaseName>.yaml` with document name
`ASR-<PascalCaseName>`.

- Prefer `aws:executeAwsApi` for one API call.
- Use `aws:executeScript` with Python 3.11 for branching or multiple calls.
- Move substantial Python into
  `source/remediation_runbooks/scripts/<Name>.py` and include it with the
  repository's `%%SCRIPT=<Name>.py%%` directive.
- End with a read-back that fails unless the resource is compliant.

The generator uses a control-based subdirectory for a portable scaffold. Move
its files into the repository layout used by neighboring built-in remediations.

### Control runbook

Create `source/playbooks/SC/ssmdocs/SC_<control_id>.ts` using
`ControlRunbookDocument` and `createControlRunbook`.

Set the security control ID, remediation name, regional/global scope, resource
parameter name, and update description. Add `resourceIdRegex` only when the
remediation API requires an extracted value. Use one capturing group and support
`aws`, `aws-us-gov`, and `aws-cn` partitions.

Create equivalent control runbooks for each additional playbook requested.

### Description

Create
`source/playbooks/SC/ssmdocs/descriptions/<control_id>.md`. Describe the
remediation, parameters, Security Hub control, and operational impact. Include a
clear impact warning when the change can interrupt a workload.

### IAM and stack integration

Update `source/lib/remediation-runbook-stack.ts` following an existing sibling:

- grant only remediation and verification actions;
- scope resources with the stack partition, account, and Region;
- let the existing construct assign the built-in remediation role name;
- add service-linked-role or `iam:PassRole` permissions only when required by
  the selected API.

Built-in roles use the solution construct's naming. Do not apply the manual
Custom Runbook `SO0111-Remediate-...` name here.

### Register the control

- Add the control runbook to
  `source/playbooks/SC/lib/control_runbooks-construct.ts`.
- Add `{ control: '<control_id>', versionAdded: '<next-version>' }` to
  `source/playbooks/SC/lib/sc_remediations.ts` and each requested playbook.

Use a future semantic solution version. Do not reduce or rewrite existing
`versionAdded` values because they determine nested-stack ownership. If a new
remediation exceeds an existing stack-size boundary, add a new
`memberStackLimits` entry rather than changing a historical limit.

### Record AI-generated provenance

Follow `ai-generated-metrics.md`. Add the exact registered identifier to
`AI_GENERATED_REMEDIATION_IDS` and add the appropriate provenance marker to each
generated artifact.

### Add tests

- Add positive and negative regex cases when `resourceIdRegex` is present.
- Add a Python test for each generated handler, using the testing pattern of its
  neighboring handlers.
- Cover remediation, idempotency, error handling, and verification behavior.

## 3. Build and check

```bash
cd source
npm run build
npm run check
```

Resolve all build, lint, type, test, coverage, and snapshot failures caused by
the change. Review new snapshots before accepting them.

For `FULL TEST`, also run the repository's complete deployment test command:

```bash
cd deployment
./run-unit-tests.sh
```

Stop after this section for `GENERATE`.

## 4. Deploy

For `FULL` or `FULL TEST`, verify the exact non-production account with STS,
then use the guarded deployment wrapper and the host's normal approval flow:

```bash
python3 "<skill-dir>/scripts/deploy_stack.py" status
python3 "<skill-dir>/scripts/deploy_stack.py" init --account-id <id> --region <region> --email <email>
python3 "<skill-dir>/scripts/deploy_stack.py" deploy
```

Run `init` only when `deployment/dev/local-config.json` does not exist. For an
additional member Region, read `deployment-topology.md` and use:

```bash
python3 "<skill-dir>/scripts/deploy_stack.py" deploy-member --region <region>
```

On a CloudFormation failure, read the failing stack events, correct the source,
then rebuild and redeploy. Do not add broad permissions to make an unexplained
failure disappear.

## 5. Verify

For `FULL TEST`:

1. Select or create a non-compliant test resource in the confirmed account.
2. Obtain a fresh failed Security Hub finding for the control.
3. Ensure the request identifies the exact live remediation target.
4. Trigger the normal ASR remediation path, asking once only if the target is unclear.
5. Wait for the SSM Automation and orchestration workflows to finish.
6. Re-read the resource, Config rule result, and Security Hub finding.
7. Require the expected resource state, `Compliance.Status == PASSED`, and
   `Workflow.Status == RESOLVED` before reporting success.

## Safety requirements

Block the change when it would:

- delete or terminate the protected resource as the primary remediation;
- disable encryption, logging, monitoring, or access control;
- grant public or cross-account access without an explicitly reviewed design;
- hardcode credentials, secrets, account IDs, or private endpoints;
- use wildcard IAM actions or unjustified wildcard resources;
- modify IAM, KMS, security groups, or resource policies without a clear
  intended scope.

Use specific IAM actions and resource ARNs. If an API does not support
resource-level permissions, document that limitation beside the policy.

## Completion report

Report:

- selected scope;
- files created and modified;
- build and test results;
- deployment stack statuses for `FULL` or `FULL TEST`;
- execution and compliance results for `FULL TEST`;
- IAM actions and resource scope;
- approval decisions and any steps not performed.
