### Document Name - ASR-CIS_1.2.0_3.x

## What does this document do?
Remediates the following CIS findings:

3.1 - Creates a log metric filter and alarm for unauthorized API calls
3.2 - Creates a log metric filter and alarm for AWS Management Console sign-in without MFA
3.3 - Creates a log metric filter and alarm for usage of "root" account
3.4 - Creates a log metric filter and alarm for for IAM policy changes
3.5 - Creates a log metric filter and alarm for CloudTrail configuration changes
3.6 - Creates a log metric filter and alarm for AWS Management Console authentication failures
3.7 - Creates a log metric filter and alarm for disabling or scheduled deletion of customer created CMKs
3.8 - Creates a log metric filter and alarm for S3 bucket policy changes
3.9 - Creates a log metric filter and alarm for AWS Config configuration changes
3.10 - Creates a log metric filter and alarm for security group changes
3.11 - Creates a log metric filter and alarm for changes to Network Access Control Lists (NACL)
3.12 - Creates a log metric filter and alarm for changes to network gateways
3.13 - Creates a log metric filter and alarm for route table changes
3.14 - Creates a log metric filter and alarm for VPC changes


## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output - Output of remediation runbook.

## Documentation Links
[CIS v1.2.0 3.1](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.1)
[CIS v1.2.0 3.2](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.2)
[CIS v1.2.0 3.3](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.3)
[CIS v1.2.0 3.4](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.4)
[CIS v1.2.0 3.5](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.5)
[CIS v1.2.0 3.6](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.6)
[CIS v1.2.0 3.7](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.7)
[CIS v1.2.0 3.8](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.8)
[CIS v1.2.0 3.9](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.9)
[CIS v1.2.0 3.10](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.10)
[CIS v1.2.0 3.11](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.11)
[CIS v1.2.0 3.12](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.12)
[CIS v1.2.0 3.13](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.13)
[CIS v1.2.0 3.14](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-3.14)
