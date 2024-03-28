### Document Name - ASR-AFSBP_1.0.0_Lambda.1

## What does this document do?
This document removes the public resource policy. A public resource policy
contains a principal "*" or AWS: "*", which allows public access to the
function. The remediation is to remove the SID of the public policy.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Documentation Links
* [AWS FSBP Lambda.1](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-lambda-1)
