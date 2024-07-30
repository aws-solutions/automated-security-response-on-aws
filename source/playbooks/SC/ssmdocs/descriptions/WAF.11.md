### Document name - AWSConfigRemediation-EnableWAFV2Logging

## What does this document do?
This runbook enables logging for an AWS Web Application Firewall (AWS WAFV2) regional and global web access control list (ACL) with the specified Amazon Kinesis Data Firehose (Kinesis Data Firehose) using the [PutLoggingConfiguration](https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_PutLoggingConfiguration.html#API_waf_PutLoggingConfiguration_ResponseSyntax) API.

## Input Parameters
* AutomationAssumeRole: (Required) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf.
* LogDestinationConfigs: (Required) The Kinesis Data Firehose ARN that you want to associate with the web ACL.
* WebAclArn: (Required) ARN of the web ACL for which logging will be enabled.

## Output Parameters
* EnableWAFV2LoggingAndVerify.Output: Success message with HTTP Response from PutLoggingConfiguration, GetLoggingConfiguration API calls or failure exception.