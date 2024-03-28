### Document Name - ASR-AFSBP_1.0.0_RDS.4

## What does this document do?
This document encrypts an unencrypted RDS snapshot by calling another SSM document

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Optional) The ARN of the role that allows Automation to perform the actions on your behalf.
* RemediationRoleName: (Optional) The name of the role that allows Automation to remediate the finding on your behalf.
* KMSKeyId: (Optional) ID, ARN or Alias for the AWS KMS Customer-Managed Key (CMK) to use to encrypt the snapshot.

## Documentation Links
* [AWS FSBP RDS.4](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-4)
