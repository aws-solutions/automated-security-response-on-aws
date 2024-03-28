### Document Name - ASR-AFSBP_1.0.0_EC2.2

## What does this document do?
This document deletes ingress and egress rules from default security
group using the AWS SSM Runbook AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output - Output from AWSConfigRemediation-RemoveVPCDefaultSecurityGroupRules SSM doc

## Documentation Links
* [AWS FSBP EC2.2](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-ec2-2)
