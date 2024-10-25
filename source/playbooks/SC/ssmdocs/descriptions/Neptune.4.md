# Document name - AWS-EnableNeptuneDbClusterDeletionProtection

## What does this document do?
The AWS-EnableNeptuneDbClusterDeletionProtection runbook will use the
[Neptune ModifyDBCluster](https://docs.aws.amazon.com/neptune/latest/apiref/API_ModifyDBCluster.html) API to enable
Deletion Protection for the specified database. An Amazon Neptune DB cluster can't be deleted while deletion
protection is enabled. To modify a cluster, the cluster must be in the available
state with an engine type of `neptune`.

## Input Parameters
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role
that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified,
Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""
* DBClusterResourceId: (Required) The Amazon Neptune DB cluster resourceId for which the
Deletion Protection should be enabled.

## Output Parameters
* EnableNeptuneDbDeletionProtection.EnableNeptuneDbDeletionProtectionResponse: The output from the
ModifyDBCluster call.