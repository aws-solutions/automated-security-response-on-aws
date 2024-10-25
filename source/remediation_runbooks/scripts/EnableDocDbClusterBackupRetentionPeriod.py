import boto3

def verify_docdb_backups_enabled(
    docdb_client,
    docdb_cluster_identifier,
    parameter_backup_retention_period,
    parameter_preferred_backup_window
):
    response = docdb_client.describe_db_clusters(DBClusterIdentifier=docdb_cluster_identifier)["DBClusters"][0]
    docdb_cluster_backup_retention_period = response["BackupRetentionPeriod"]
    docdb_cluster_preferred_backup_window = response.get("PreferredBackupWindow")

    if parameter_preferred_backup_window:
        return (docdb_cluster_backup_retention_period == parameter_backup_retention_period and 
        (docdb_cluster_preferred_backup_window == parameter_preferred_backup_window))

    return (docdb_cluster_backup_retention_period == parameter_backup_retention_period)

def handler(event, context):
    docdb_client = boto3.client("docdb")
    docdb_cluster_identifier = event["DBClusterIdentifier"]
    docdb_resource_identifier = event["DBClusterResourceId"]
    docdb_backup_retention_period = event["BackupRetentionPeriod"]
    docdb_preferred_backup_window = event.get("PreferredBackupWindow")

    if verify_docdb_backups_enabled(
        docdb_client, docdb_cluster_identifier,
        docdb_backup_retention_period,
        docdb_preferred_backup_window
    ):
        success_message = "Verification of backups enabled for Amazon DocumentDB Cluster is successful."
        return {"VerifyDbClusterBackupsEnabled": success_message}
    raise Exception(
        f"VERIFICATION STEP FAILED. DOCUMENT DB RESOURCE ID {docdb_resource_identifier} "
        "BACKUPS WERE NOT ENABLED PER PARAMETERS."
    )