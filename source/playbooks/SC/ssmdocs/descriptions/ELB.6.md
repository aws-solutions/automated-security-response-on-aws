### Document name - AWSConfigRemediation-EnableELBDeletionProtection

## What does this document do?
This document enables deletion protection for the specified AWS Elastic Load Balancer using the [ModifyLoadBalancerAttributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ModifyLoadBalancerAttributes.html) API.

## Input Parameters
* LoadBalancerArn: (Required) The Amazon Resource Name (ARN) of the load balancer.
* AutomationAsssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* EnableAndVerifyDeletionProtection.Output - The standard HTTP response from ModifyLoadBalancerAttributes API.