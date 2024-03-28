### Document Name - ASR-AFSBP_1.0.0_Config.1
## What does this document do?
Enables AWS Config:
* Turns on recording for all resources.
* Creates an encrypted bucket for Config logging.
* Creates a logging bucket for access logs for the config bucket
* Creates an SNS topic for Config notifications
* Creates a service-linked role

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Documentation Links
* [AWS FSBP Config.1](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-config-1)
