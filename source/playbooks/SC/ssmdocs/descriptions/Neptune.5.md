# Document name - AWS-EnableNeptuneDbBackupRetentionPeriod

## What does this document do?
The AWS-EnableNeptuneDbBackupRetentionPeriod runbook will use the Amazon Neptune 
[ModifyDBCluster](https://docs.aws.amazon.com/neptune/latest/apiref/API_ModifyDBCluster.html) API to enable 
automated backups with a backup retention period between 7 and 35 days for the specified Amazon Neptune DB cluster. 
The Amazon Neptune DB cluster must be in an available state and the engine type must be set to `neptune`.

## Input Parameters
* AutomationAssumeRole: (Optional) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role
that allows Systems Manager Automation to perform the actions on your behalf. If no role is specified,
Systems Manager Automation uses the permissions of the user that starts this runbook.
* Default: ""
* DbClusterResourceId: (Required) The Amazon Neptune DB cluster resourceId for which the 
Backup Retention Period should be enabled.
* BackupRetentionPeriod: (Required) The number of days for which automated backups are retained. 
Must be a value from 7-35 days.
* PreferredBackupWindow: (Optional) A daily time range value of at least 30 minutes, in 
Universal Time Coordinated (UTC) in the format hh24:mm-hh24:mm (e.g., 07:14-07:44). 
Must not conflict with the preferred maintenance window.
* Default: ""

## Output Parameters
* ModifyNeptuneDbRetentionPeriod.ModifyDbClusterResponse: Response from the ModifyDBCluster API call.
* VerifyNeptuneDbBackupsEnabled.VerifyDbClusterBackupsEnabled: Output of the verify step indicating 
successful modification of the Neptune DB cluster.