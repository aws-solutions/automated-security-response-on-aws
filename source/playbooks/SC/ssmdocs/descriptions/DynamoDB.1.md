# Document name - AWS-EnableDynamoDbAutoscaling

## What does this document do?
The AWS-EnableDynamoDbAutoscaling runbook will enable Application Autoscaling for an existing DynamoDB Table which is 
configured for provisioned capacity in order to maintain availability using the [RegisterScalableTarget](https://docs\
.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html) and [PutScalingPolicy](https://\
docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScalingPolicy.html) APIs. Amazon DynamoDB auto scaling 
uses the AWS Application Auto Scaling service to dynamically adjust provisioned throughput capacity on your behalf, in 
response to actual traffic patterns. For more information, see Managing throughput capacity 
automatically with DynamoDB auto scaling in the [Amazon DynamoDB User Guide](https://docs.aws.amazon.com/amazondynamo\
db/latest/developerguide/AutoScaling.html).

## Input Parameters
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role
that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified,
Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""
* TableName: (Required) The name of the DynamoDB Table on which to enable Application Autoscaling.
* MinReadCapacity: (Required) The minimum number of provisioned-throughput read units for the DynamoDB Table.
* MaxReadCapacity: (Required) The maximum number of provisioned-throughput read units for the DynamoDB Table.
* TargetReadCapacityUtilization: (Required) The desired target read capacity utilization, expressed as a percentage, 
between 20-90%. 
* ReadScaleOutCooldown: (Required) The amount of time, in seconds, to wait for a previous read capacity scale-out 
activity to take effect.
* ReadScaleInCooldown: (Required) The amount of time, in seconds, after a read capacity scale-in activity completes 
before another scale-in activity can start.
* MinWriteCapacity: (Required) The minimum number of provisioned-throughput write units for the DynamoDB Table.
* MaxWriteCapacity: (Required) The maximum number of provisioned-throughput write units for the DynamoDB Table.
* TargetWriteCapacityUtilization: (Required) The desired target write capacity utilization, expressed as a percentage, 
between 20-90%. 
Application Autoscaling ensures the ratio of consumed capacity to provisioned capacity stays at or near this value.
* WriteScaleOutCooldown: (Required) The amount of time, in seconds, to wait for a previous write capacity scale-out 
activity to take effect.
* WriteScaleInCooldown: (Required) (Required) The amount of time, in seconds, after a write capacity scale-in activity 
completes before another scale-in activity can start.

## Output Parameters
* RegisterAppAutoscalingTargetWrite.Response
* PutScalingPolicyWrite.Response
* RegisterAppAutoscalingTargetRead.Response
* PutScalingPolicyRead.Response
* VerifyDynamoDbAutoscalingEnabled.DynamoDbAutoscalingEnabledResponse