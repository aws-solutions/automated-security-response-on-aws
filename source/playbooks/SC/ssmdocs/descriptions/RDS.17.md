### Document name - AWSConfigRemediation-EnableCopyTagsToSnapshotOnRDSDBInstance

## What does this document do?
The document enables CopyTagsToSnapshot on a given Amazon RDS database instance using the [ModifyDBInstance API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html).

## Input Parameters
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
* DbiResourceId: (Required) Resource ID of the Amazon RDS DB Instance for which `CopyTagsToSnapshot` needs to be enabled.
* ApplyImmediately: (Optional) A value that indicates whether the modifications in this request and any pending modifications are asynchronously applied as soon as possible, regardless of the PreferredMaintenanceWindow setting for the DB instance. By default, this parameter is disabled.
* Default: false

## Output Parameters
* ModifyDBInstanceResponse.Output: The response of the ModifyDBInstance API call.