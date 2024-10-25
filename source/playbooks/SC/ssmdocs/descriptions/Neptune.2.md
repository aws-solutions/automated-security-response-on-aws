# Document name - AWS-EnableNeptuneDbAuditLogsToCloudWatch

## What does this document do?
The AWS-EnableNeptuneDbAuditLogsToCloudWatch runbook will utilize the
[ModifyDBCluster](https://docs.aws.amazon.com/neptune/latest/apiref/API_ModifyDBCluster.html) API call to enable 
Amazon Neptune DB clusters to send audit logs to Amazon CloudWatch. The Amazon Neptune DB cluster must be in an 
available state and the engine type must be set to `neptune`.

## Input Parameters
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) 
role that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified,
Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""
* DbClusterResourceId: (Required) The Amazon Neptune DB cluster resourceId for which the audit logging should be 
enabled.

## Output Parameters
* EnableNeptuneDbAuditLogs.EnableNeptuneDbAuditLogsResponse: The output from the ModifyDBCluster call.
* VerifyNeptuneDbAuditLogs.VerifyNeptuneDbAuditLogsResponse: The output of the DescribeDBCluster call.