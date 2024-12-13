### Document Name - ASR-SC_EC2.10

## What does this document do?
This document created and attaches a service interface endpoint to the given VPC. By default, it allows access for all subnets in the VPC.
## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [EC2.10 Control](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-10)