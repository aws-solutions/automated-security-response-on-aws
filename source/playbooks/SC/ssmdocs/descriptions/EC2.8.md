  ### Document Name - AWSConfigRemediation-EnforceEC2InstanceIMDSv2

  ## What does this document do?
  This document is used to enforce Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version to Instance Metadata Service Version 2 (IMDSv2) on a given Amazon EC2 instance using [ModifyInstanceMetadataOptions](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceMetadataOptions.html) API.

  ## Input Parameters
  * AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  * InstanceId: (Required) The ID of the Amazon EC2 instance.

  ## Output Parameters
  * ModifyInstanceMetadataOptions.Output: The standard HTTP response from the ModifyInstanceMetadataOptions API.
