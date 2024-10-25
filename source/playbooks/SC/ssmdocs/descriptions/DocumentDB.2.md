# AWS-EnableDocDbClusterBackupRetentionPeriod

## What does this document do?
The AWS-EnableDocDbClusterBackupRetentionPeriod runbook enables the backup retention period using the 
[ModifyDBCluster](https://docs.aws.amazon.com/documentdb/latest/developerguide/API_ModifyDBCluster.html) API to 
update the retention period for an Amazon DocumentDB cluster to a value between 7 days to 35 days. This feature 
sets the total number of days for which an automated backup is retained. To modify a cluster, the cluster must be 
in the available state with an engine type of `docdb`.

## Input Parameters
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role
that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified,
Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""
* DBClusterResourceId: (Required) The Amazon Document DB cluster resourceId for which the backup retention period 
should be enabled.
* BackupRetentionPeriod: (Required) The number of days for which automated backups are retained. 
Must be a value from 7-35 days.
* PreferredBackupWindow: (Optional) A daily time range value of at least 30 minutes, in Universal Time Coordinated 
(UTC) in the format hh24:mm-hh24:mm (e.g., 07:14-07:44). Must not conflict with the preferred maintenance window.

## Output Parameters
* ModifyDocDbRetentionPeriod.ModifyDbClusterResponse: Response from the ModifyDBCluster API call.
* VerifyDocDbBackupsEnabled.VerifyDbClusterBackupsEnabledResponse: Output of the verify step indicating successful 
modification of the DocumentDB cluster.