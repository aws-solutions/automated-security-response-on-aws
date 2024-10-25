### Document name - AWSConfigRemediation-DropInvalidHeadersForALB

## What does this document do?
This runbook enables the application load balancer you specify to remove HTTP headers with invalid headers using the [ModifyLoadBalancerAttributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ModifyLoadBalancerAttributes.html) API.

## Input Parameters
* AutomationAssumeRole: (Required) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf.
* LoadBalancerArn: (Required) The Amazon Resource Name (ARN) of the load balancer that you want to drop invalid headers.

## Output Parameters
* DropInvalidHeaders.Output: The standard HTTP response from the ModifyLoadBalancerAttributes API.