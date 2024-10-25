# AWS-EnableStepFunctionsStateMachineLogging

## What does this document do?
The AWS-EnableStepFunctionsStateMachineLogging runbook will enable or update the logging on the specified AWS Step 
Functions State Machine using the 
[UpdateStateMachine](https://docs.aws.amazon.com/step-functions/latest/apireference/API_UpdateStateMachine.html) 
API. If no logging configuration currently exists on the AWS State Machine, one will be created. IF a logging 
configuration does exist, it will be updated during runbook execution. The minimum logging level must be set 
to ALL, ERROR, or FATAL.

## Input Parameters
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role
that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified,
Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""
* StateMachineArn: (Required) The Amazon Resource Name (ARN) of the state machine.
* Level: (Required) Defines which category of execution history events are logged. Values can be ALL, ERROR, or FATAL.
* LogGroupArn: (Required) The ARN of the the Amazon CloudWatch log group to which you want your logs emitted to.
* IncludeExecutionData: (Optional) Determines whether execution data is included in your log.
* Default: "False"
* TracingConfiguration: (Optional) Selects whether AWS X-Ray tracing is enabled.
* Default: "False"

## Output Parameters
* EnableStepFunctionsStateMachineLogging.Response: Response from the UpdateStateMachine API call.