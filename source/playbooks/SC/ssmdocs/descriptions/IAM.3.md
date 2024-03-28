### Document Name - ASR-AFSBP_1.0.0_IAM.3

## What does this document do?
This document disables active keys that have not been rotated for more than 90 days. Note that this remediation is **DISRUPTIVE**.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS FSBP v1.0.0 IAM.3](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-iam-3)
