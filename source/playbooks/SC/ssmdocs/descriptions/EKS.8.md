# Document name - AWSSupport-CollectEKSInstanceLogs

## What does this document do?
The **AWSSupport-CollectEKSInstanceLogs** runbook helps collect Amazon Elastic Kubernetes Service (Amazon EKS) specific logs from the specified Amazon EC2 instance and upload it to a specified Amazon S3 bucket.

## Input Parameters
* EKSInstanceId: (Required) The ID of your Amazon EKS EC2 instance where you want to collect the log bundle from.
* LogDestination: (Optional) The Amazon S3 bucket name in your account where you want to upload the troubleshooting logs. Make sure the bucket policy does not grant unnecessary read/write permissions to parties that do not need access to the collected logs.
* Default: ""
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified, Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""