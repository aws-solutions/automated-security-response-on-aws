import boto3
import botocore

def handler(event, context):
    neptune_cluster_id = event["DBClusterIdentifier"]
    neptune_resource_identifier = event["DbClusterResourceId"]
    neptune_client = boto3.client("neptune")

    try:
        response = neptune_client.describe_db_clusters(DBClusterIdentifier=neptune_cluster_id)["DBClusters"][0]
    except botocore.exceptions.ClientError as error:
        raise Exception from error

    cloudwatch_logging_config = response.get("EnabledCloudwatchLogsExports")
    if cloudwatch_logging_config and "audit" in cloudwatch_logging_config:
        success_message = "Verification of CloudWatch audit logging enabled for Neptune cluster is successful."
    return {"VerifyNeptuneDbAuditLogsEnabled": success_message}
    
    raise Exception(
        f"VERIFICATION STEP FAILED. NEPTUNE RESOURCE ID {neptune_resource_identifier} CLOUDWATCH AUDIT LOGS "
        "WERE NOT ENABLED PER PARAMETERS."
    )