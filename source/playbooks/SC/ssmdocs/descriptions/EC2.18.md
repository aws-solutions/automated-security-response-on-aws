### Document Name - ASR-AFSBP_1.0.0_EC2.18
 
## What does this document do?
This document revokes inbound security group rules that allow unrestricted access to ports that are not authorized.
Authorized ports are listed in authorizedTcpPorts and authorizedUdpPorts parameters.
 
## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
 
## Output Parameters
* Remediation.Output
 
## Documentation Links
* [AFSBP v1.0.0 EC2.18](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-18)