### Document Name - ASR-Macie.SensitiveDataS3Object

## What does this document do?

This document remediates Amazon Macie sensitive data findings on S3 objects by enabling
all four S3 Block Public Access settings on the containing bucket:
`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`.

This remediation is a **first line of defense**. The Security Hub finding is set to
`IN_PROGRESS` because manual investigation is required to assess the scope of potential
data exposure and determine whether the sensitive data needs to be deleted, encrypted,
or relocated before the finding can be resolved.

## Input Parameters

- Finding: (Required) Security Hub finding details JSON (OCSF format)
- AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters

- Remediation.Output

## Documentation Links

- [Macie Sensitive Data Finding Types](https://docs.aws.amazon.com/macie/latest/user/findings-types.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
