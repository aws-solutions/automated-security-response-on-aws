# ASR Custom Remediation IAM

Captures the IAM boilerplate that every ASR Custom runbook needs before its SSM
Automation document can execute. Referenced by the `asr-remediation-author`
agent during the DEPLOY phase.

## Role naming

`SO0111-Remediate-<Shortname>-<Version>-<ControlId>`

Examples:

- `SO0111-Remediate-SC-2.0.0-Inspector.4`
- `SO0111-Remediate-SC-2.0.0-EC2.182`

**There is no `Custom` segment.** The Orchestrator derives the role name from the
finding, in `source/Orchestrator/resolve_ssm_doc_for_finding.py`:

```python
remediation_role = f"SO0111-Remediate-{shortname}-{standard_version}-{remediation_control}"
```

A `SO0111-Remediate-Custom-SC-…` role is never looked up by anything. Worse, the
failure is quiet: `exec_ssm_doc.py` checks whether the derived role exists and, if
not, falls back to `SO0111-ASR-Orchestrator-Member` as the `AutomationAssumeRole`.
The execution then starts and fails inside a step on a missing permission, so a
misnamed role presents as a policy bug rather than a naming bug.

## Trust policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ssm.amazonaws.com",
        "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/SO0111-ASR-Orchestrator-Member"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Both principals are required:

- `ssm.amazonaws.com` — SSM Automation service invokes the document.
- `SO0111-ASR-Orchestrator-Member` — the ASR orchestrator Step Function starts
  the execution on the member account.

## Minimum inline policy (name it `ASR-Custom-Runbook-Remediation`)

Start from only the APIs the runbook actually calls. Minimum template:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["<service>:<EnableApi>", "<service>:<DescribeApi>"],
      "Resource": "*"
    }
  ]
}
```

## Deriving the base policy from step actions

Build the inline policy from the APIs the runbook's steps **actually call**, not
from guessing. Two layers contribute permissions:

1. **The AWS APIs invoked by the step body** — for `aws:executeAwsApi` this is
   the `Service`/`Api` pair directly; for `aws:executeScript` it's every
   `boto3`/SDK call inside the script; for `aws:assertAwsResourceProperty` /
   `aws:waitForAwsResourceProperty` it's the `describe`/`get` being asserted on.
2. **The action's own IAM prerequisites** — several SSM Automation actions
   require IAM beyond the AWS API they wrap. Add these when the runbook uses the
   action:

| Automation action                     | Extra IAM the action itself needs                                                                                                                                            |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `aws:changeInstanceState`             | `ec2:DescribeInstances`, `ec2:StartInstances`, `ec2:StopInstances`, `ec2:TerminateInstances`                                                                                 |
| `aws:createImage`                     | `ec2:CreateImage`, `ec2:DescribeImages`, `ec2:DescribeInstances`                                                                                                             |
| `aws:copyImage`                       | `ec2:CopyImage`, `ec2:DescribeImages`; `kms:CreateGrant` if KMS-encrypting                                                                                                   |
| `aws:createTags`                      | `ec2:CreateTags` (EC2) or `ssm:AddTagsToResource` (SSM resources)                                                                                                            |
| `aws:runCommand`                      | `ssm:SendCommand`, `ssm:GetCommandInvocation`; `s3:PutObject` if S3 output                                                                                                   |
| `aws:runInstances`                    | `ec2:RunInstances`, `ec2:DescribeInstances`; **`iam:PassRole`** for the instance profile                                                                                     |
| `aws:executeScript`                   | Only when the script calls AWS APIs or logs to CloudWatch: `ssm:GetParameter`, `kms:Decrypt` (CMK), `s3:GetObject` (attachments) — plus whatever the script's SDK calls need |
| `aws:executeAutomation`               | `ssm:StartAutomationExecution`; **`iam:PassRole`** if the child automation uses its own assume role                                                                          |
| `aws:executeStateMachine`             | `states:StartExecution`, `states:DescribeExecution`, `states:StopExecution`                                                                                                  |
| `aws:invokeLambdaFunction`            | `lambda:InvokeFunction`                                                                                                                                                      |
| `aws:createStack` / `aws:deleteStack` | `cloudformation:CreateStack`/`DeleteStack`, `cloudformation:DescribeStacks`, plus permissions for every resource in the template                                             |

`iam:PassRole` is the one most often missed — scope it to the exact role ARN
being passed, never `*`.

## ARN and partition scoping

`Resource: "*"` is acceptable only for APIs that don't support resource-level
permissions. Otherwise scope to the concrete ARN. When authoring for
non-commercial partitions, use the right partition in every ARN — `aws-cn`
(China) or `aws-us-gov` (GovCloud) — not the default `aws`. The account segment
should be the member account ID, not `*`, once known.

## Per-service gotchas (expand the policy when any of these apply)

### Inspector2 (`inspector2:Enable`)

Any `inspector2:Enable` call on an account that has never enabled any Inspector
resource type will create the service-linked role
`AWSServiceRoleForAmazonInspector2`. Without the extra permission, the Enable
call fails with `AccessDeniedException ... iam:CreateServiceLinkedRole`.

Add:

```json
{
  "Effect": "Allow",
  "Action": "iam:CreateServiceLinkedRole",
  "Resource": "arn:aws:iam::*:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2",
  "Condition": {
    "StringLike": { "iam:AWSServiceName": "inspector2.amazonaws.com" }
  }
}
```

Applies to Inspector.1/2/3/4/5 runbooks. The service-linked role may
already exist, but include this permission so the remediation also works in a new
account.

### GuardDuty (`guardduty:CreateDetector`, feature enablement)

`guardduty:CreateDetector` creates `AWSServiceRoleForAmazonGuardDuty` on first
use. Add:

```json
{
  "Effect": "Allow",
  "Action": "iam:CreateServiceLinkedRole",
  "Resource": "arn:aws:iam::*:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
  "Condition": {
    "StringLike": { "iam:AWSServiceName": "guardduty.amazonaws.com" }
  }
}
```

Applies to GuardDuty.1/7/11/12/13 remediations.

### Macie (`macie2:EnableMacie`)

```json
{
  "Effect": "Allow",
  "Action": "iam:CreateServiceLinkedRole",
  "Resource": "arn:aws:iam::*:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie",
  "Condition": {
    "StringLike": { "iam:AWSServiceName": "macie.amazonaws.com" }
  }
}
```

Applies to Macie.1.

### Config (`config:PutConfigurationRecorder`)

Needs `iam:PassRole` on the Config service role the customer has already created
in the member account. Scope to the role ARN, not `*`.

### KMS encryption on customer-managed keys

If the remediation targets a customer-managed KMS key (most S3/DynamoDB/SNS
encryption flows), the policy needs both the service action
(`kms:GenerateDataKey`, `kms:Decrypt`, etc.) and `kms:DescribeKey`. The
`Resource` for KMS actions should be `*` with a `Condition` on `kms:KeyArn` or
`aws:ResourceAccount` — not a blanket `*`.

## Creating the role with the AWS CLI

Write policy files to `.tmp/<ControlId>-trust.json` and
`.tmp/<ControlId>-policy.json`, then:

```bash
ROLE="SO0111-Remediate-SC-2.0.0-<ControlId>"

aws iam create-role \
  --role-name "$ROLE" \
  --assume-role-policy-document file://.tmp/<ControlId>-trust.json \
  --description "ASR custom remediation role for <ControlId>"

aws iam put-role-policy \
  --role-name "$ROLE" \
  --policy-name ASR-Custom-Runbook-Remediation \
  --policy-document file://.tmp/<ControlId>-policy.json
```

If the role already exists, skip `create-role`; `put-role-policy` is idempotent.
Update the trust policy with `aws iam update-assume-role-policy` if you need to
add a principal.

## Cross-checking an existing sibling

To reuse the exact shape of a similar working role:

```bash
aws iam get-role --role-name SO0111-Remediate-SC-2.0.0-Inspector.2 \
  --query 'Role.AssumeRolePolicyDocument' --output json
aws iam get-role-policy --role-name SO0111-Remediate-SC-2.0.0-Inspector.2 \
  --policy-name ASR-Custom-Runbook-Remediation \
  --query 'PolicyDocument' --output json
```

The roles the **solution** deploys for its built-in remediations are a different
family — `SO0111-<RemediationName>-<namespace>`, from
`remediationRoleName` in `source/lib/remediation-runbook-stack.ts` — so there is
usually no `SO0111-Remediate-SC-…` sibling to copy in a fresh account. Read a
built-in's policy for the action list, but keep your own role's name in the
convention-derived form.

Do **not** blindly copy a sibling's policy without adding the SLR permission if
the target control is the first of its service family in a new account.

## Cleanup

List manually created remediation roles before removing any of them:

```bash
aws iam list-roles \
  --query 'Roles[?starts_with(RoleName, `SO0111-Remediate-`)].RoleName' \
  --output text
```

Confirm each role's control, account, and current use before deletion.
