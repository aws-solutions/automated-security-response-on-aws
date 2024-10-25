import boto3
import botocore

def enable_backups(rds_client,event):
    try:
        parameter_names = ["DBInstanceIdentifier", "ApplyImmediately", "BackupRetentionPeriod", "PreferredBackupWindow"]
        modify_params = {p: event[p] for p in parameter_names if event.get(p)}
        rds_client.modify_db_instance(**modify_params)
    except botocore.exceptions.ClientError as error:
        if "member of a cluster" in error.response["Error"]["Message"]:
            raise Exception(f"DB INSTANCE {event['DBInstanceIdentifier']} MODIFICATION FAILED. DB INSTANCE IS A MEMBER OF A CLUSTER, BACKUP RETENTION MANAGED ON THE DB CLUSTER.")
        elif "backup window and maintenance window must not overlap" in error.response["Error"]["Message"]:
            raise Exception(f"DB INSTANCE {event['DBInstanceIdentifier']} MODIFICATION FAILED.  BACKUP WINDOW AND MAINTENANCE WINDOW MUST NOT OVERLAP.")
        elif "backup window must be at least 30 minutes" in error.response["Error"]["Message"]:
            raise Exception(f"DB INSTANCE {event['DBInstanceIdentifier']} MODIFICATION FAILED. BACKUP WINDOW MUST BE AT LEAST 30 MINUTES.")
        else:
            raise error

def verify_backups_enabled(
    rds_client, 
    db_instance_identifier, 
    backup_retention_period, 
    preferred_backup_window
):
    db_instance = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)["DBInstances"][0]
    properties = ["BackupRetentionPeriod","PreferredBackupWindow"]
    retention_periods, backup_windows = ([db_instance["PendingModifiedValues"].get(p), db_instance[p]] for p in properties)
    return (backup_retention_period in retention_periods and 
        (not preferred_backup_window or preferred_backup_window in backup_windows))

def handler(event, context):
    rds_client = boto3.client("rds")
    db_instance_identifier = event["DBInstanceIdentifier"]
    enable_backups(rds_client, event)
    if verify_backups_enabled(
        rds_client, 
        db_instance_identifier, 
        event["BackupRetentionPeriod"], 
        event.get("PreferredBackupWindow")
    ):
        return {"output": "Verification of backups enabled for Amazon RDS DB instance is successful."}
    raise Exception(f"VERIFICATION FAILED. DB RESOURCE ID {db_instance_identifier} BACKUPS NOT ENABLED PER PARAMETERS.")