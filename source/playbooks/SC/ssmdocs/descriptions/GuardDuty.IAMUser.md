### Document Name - ASR-GuardDuty.IAMUser

## What does this document do?

This document remediates Amazon GuardDuty IAM credential compromise findings by containing
the compromised IAM user using the AWS-managed `AWSSupport-ContainIAMPrincipal` runbook.
Containment disables all access keys, removes console access, and attaches a deny-all policy.
The original IAM configuration is backed up to S3 to enable rollback via the ASR Web UI.

This remediation is a **first line of defense**. The Security Hub finding is set to
`IN_PROGRESS` because manual investigation is required to determine the scope of unauthorized
access before the finding can be resolved.

## Input Parameters

- Finding: (Required) Security Hub finding details JSON (OCSF format)
- Action: (Optional) `Contain` (default) or `Restore`
- RemediationConfigBucket: (Required) S3 bucket for IAM configuration backups
- AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters

- Remediation.Output

## Documentation Links

- [GuardDuty IAM Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [AWSSupport-ContainIAMPrincipal](https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-awssupport-containiamprincipal.html)
