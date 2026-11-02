  ### Document Name - ASR-NIST_800_53_AutoScaling.3
  
  ## What does this document do?
  This document migrates the Auto Scaling group to a Launch Template that requires IMDSv2. Auto Scaling groups still backed by a Launch Configuration are migrated to a Launch Template as part of the remediation. The original non-compliant launch configuration is deleted once no Auto Scaling group still references it.
  
  ## Input Parameters
  * Finding: (Required) Security Hub finding details JSON
  * AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  
  ## Output Parameters
  * Remediation.Output - Output from the remediation
  
  ## Documentation Links
  * [NIST AutoScaling.3](https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html#autoscaling-3)