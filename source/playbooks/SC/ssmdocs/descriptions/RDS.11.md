### Document name - AWSConfigRemediation-EnableRDSInstanceBackup

## What does this document do?
This document enables backups on an Amazon RDS DB instance using the [ModifyDBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html) API.
Note: This is not applicable for Amazon Aurora.

## Input Parameters
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
* DbiResourceId: (Required) Resource ID of the Amazon RDS database instance for which backups need to be enabled.
* ApplyImmediately: (Optional) A value that indicates whether the modifications in this request and any pending modifications are asynchronously applied as soon as possible, regardless of the PreferredMaintenanceWindow setting for the DB instance. By default, this parameter is disabled.
* Default: false
* BackupRetentionPeriod: (Required) A positive integer value that indicates the number of days to retain automated backups.
* PreferredBackupWindow: (Optional) A daily time range value of at least 30 minutes, in Universal Time Coordinated (UTC).
* Default: ""

## Output Parameters
* EnableBackupsOnRDSInstanceAndVerify.Output