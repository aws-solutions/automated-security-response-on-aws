### Document Name - ASR-SC_SSM.1

## What does this document do?
This document adds the necessary permissions for SSM to begin managing the EC2 Instance.

## Input Parameters
* InstanceArn: (Required) EC2 Instance ARN
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
* RemediationRole: (Required) The ARN of the role that with SSM managed permissions for EC2.
* InstanceProfile: (Required) The name of the Instance profile with SSM managed permissions for EC2.

## Output Parameters
* Remediation.Output

## Documentation Links
* [SSM.1](https://docs.aws.amazon.com/securityhub/latest/userguide/ssm-controls.html#ssm-1)