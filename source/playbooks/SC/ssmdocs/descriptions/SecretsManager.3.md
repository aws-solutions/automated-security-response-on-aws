### Document Name - ASR-AFSBP_1.0.0_SecretsManager.3
 
## What does this document do?
This document deletes a secret that has been unused for the number of days specified in the unusedForDays parameter (Default: 90 days).
 
## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
* SecretARN: (Required) The ARN of the Secrets Manager secret.
 
## Output Parameters
* Remediation.Output
 
## Documentation Links
* [AFSBP v1.0.0 SecretsManager.3](https://docs.aws.amazon.com/securityhub/latest/userguide/secretsmanager-controls.html#secretsmanager-3)