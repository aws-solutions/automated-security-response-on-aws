 ### Document Name - AWSConfigRemediation-EnablePITRForDynamoDbTable

## What does this document do?
This document enables `PointInTimeRecovery` on an Amazon DynamoDB table using the [UpdateContinuousBackups](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateContinuousBackups.html) API.

## Input Parameters
* TableName: (Required) Name of the Amazon DynamoDB table.
* Example: dynamodb-pitr-example
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* EnablePITRForDynamoDbTable.UpdateContinuousBackupsResponse: The standard HTTP response from the UpdateContinuousBackups API.