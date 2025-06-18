### Document Name - ASR-AFSBP_1.0.0_AutoScaling.1

## What does this document do?
This document enables ELB healthcheck on a given AutoScaling Group using the [UpdateAutoScalingGroup] API.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* HealthCheckGracePeriod: (Optional) Health check grace period when ELB health check is Enabled
Default: 30 seconds
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS FSBP AutoScaling.1](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-autoscaling-1)
