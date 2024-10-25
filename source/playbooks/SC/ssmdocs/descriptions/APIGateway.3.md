### Document name - AWSConfigRemediation-EnableApiGatewayTracing

## What does this document do?
This document enables tracing on an Amazon API Gateway Stage using the [UpdateStage](https://docs.aws.amazon.com/apigateway/api-reference/link-relation/stage-update/) API.
Please note, AWS Config is required to be enabled in this region for this document to work as it requires the resource ID recorded by the AWS Config service.

## Input Parameters
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
* StageArn: (Required) The Amazon API Gateway Stage ARN.

## Output Parameters
* EnableTracingAndVerify.Output: Success message or failure exception.