### Document Name - ASR-SC_GuardDuty.4

## What does this document do?
This document tags a GuardDuty detector with the required tags specified in Security Hub. If no required tags are specified, the document adds a default tag to remediate the finding.
## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [GuardDuty.4 Control](https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-4)