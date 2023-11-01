description: |
  ### Document Name - AWSConfigRemediation-RemoveUnrestrictedSourceIngressRules

  ## What does this document do?
  This runbook removes all ingress rules from the security group you specify that allow traffic from all source addresses using the [RevokeSecurityGroupIngress](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html) API.

  ## Input Parameters
  * SecurityGroupId: (Required) The ID of the security group that you want to remove ingress rules that allow traffic from all source addresses from.
  * AutomationAssumeRole: (Required) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf.

  ## Output Parameters
  * RemoveUnrestrictedIngressRulesAndVerify.Response - The standard HTTP response from the RevokeSecurityGroupIngress API.