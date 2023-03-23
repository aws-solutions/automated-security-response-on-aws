### Document Name - ASR-PCI_3.2.1_EC2.5

## What does this document do?
Removes public access to remove server administrative ports from an EC2 Security Group

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output - Output of AWS-DisablePublicAccessForSecurityGroup runbook.

## Documentation Links
* [PCI v3.2.1 EC2.5](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-pci-controls.html#pcidss-ec2-5)
* [CIS v1.2.0 4.1](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.1)
* [CIS v1.2.0 4.2](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-4.2)
