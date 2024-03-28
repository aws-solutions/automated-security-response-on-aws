### Document Name - ASR-AFSBP_1.0.0_RDS.16

## What does this document do?
This document enables `Copy tags to snapshots` on a given Amazon RDS cluster by calling another SSM document.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output - The standard HTTP response from the ModifyDBCluster API.

## Documentation Links
* [AWS FSBP RDS.16](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-16)
