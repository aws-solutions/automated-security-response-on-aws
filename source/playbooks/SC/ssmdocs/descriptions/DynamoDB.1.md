### Document Name - ASR-SC_2_0_0_DynamoDB.1

## What does this document do?
This document registers a DynamoDB table in provisioned mode with Application Auto Scaling and creates a new scaling policy based on the
parameters provided by the DynamoDB.1 control in Security Hub.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output - Output from the remediation

## Documentation Links
* [DynamoDB.1](https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html#dynamodb-1)