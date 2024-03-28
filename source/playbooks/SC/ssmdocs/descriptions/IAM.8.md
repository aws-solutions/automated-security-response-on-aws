### Document Name - ASR-AFSBP_1.0.0_IAM.8

## What does this document do?
This document ensures that credentials unused for 90 days or greater are disabled.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output - Output of remediation runbook

SEE AWSConfigRemediation-RevokeUnusedIAMUserCredentials

## Documentation Links
* [AWS FSBP IAM.8](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-iam-8)
