import boto3
import botocore

def verify_neptune_backups_enabled(
    neptune_client, 
    neptune_cluster_identifier, 
    parameter_backup_retention_period, 
    parameter_preferred_backup_window
):
    try:
        response=neptune_client.describe_db_clusters(DBClusterIdentifier = neptune_cluster_identifier)["DBClusters"][0]
    except botocore.exceptions.ClientError as error:
        raise Exception from error

    neptune_cluster_backup_retention_period = response["BackupRetentionPeriod"]
    neptune_cluster_preferred_backup_window = response.get("PreferredBackupWindow")

    if parameter_preferred_backup_window:
        return (neptune_cluster_backup_retention_period == parameter_backup_retention_period and 
            (neptune_cluster_preferred_backup_window == parameter_preferred_backup_window))

    return (neptune_cluster_backup_retention_period == parameter_backup_retention_period)

def handler(event, context):
    neptune_client = boto3.client("neptune")
    neptune_cluster_identifier = event["DbClusterIdentifier"]
    neptune_backup_retention_period = event["BackupRetentionPeriod"]
    neptune_preferred_backup_window = event.get("PreferredBackupWindow")
    neptune_resource_identifier = event["DbClusterResourceId"]

    if verify_neptune_backups_enabled(
        neptune_client, 
        neptune_cluster_identifier, 
        neptune_backup_retention_period, 
        neptune_preferred_backup_window
    ):
        success_message = "Verification of backups enabled for Amazon Neptune DB cluster is successful."
        return {"VerifyNeptuneClusterBackupsEnabled": success_message}
    raise Exception(
        f"VERIFICATION STEP FAILED. NEPTUNE RESOURCE ID {neptune_resource_identifier} "
        "BACKUPS WERE NOT ENABLED PER PARAMETERS."
    )