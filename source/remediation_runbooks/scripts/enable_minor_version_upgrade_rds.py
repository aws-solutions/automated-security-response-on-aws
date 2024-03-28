# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})

multi_az_cluster_engines = ["mysql", "postgres"]


def connect_to_rds():
    return boto3.client("rds", config=boto_config)


def lambda_handler(event, _):
    """
    Enable auto minor version upgrades on an instance or a Multi-AZ Cluster

    `event` should have the following keys and values:
    `DBInstanceIdentifier`: The identifier of the database instance that is to be modified.

    `context` is ignored
    """
    db_instance_id = event["DBInstanceIdentifier"]

    rds = connect_to_rds()

    found_instance = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)

    instance_info = found_instance["DBInstances"][0]

    response = False

    if "DBClusterIdentifier" in instance_info.keys():
        if multi_az_check(instance_info["DBClusterIdentifier"]):
            cluster_id = instance_info["DBClusterIdentifier"]
            enable_minor_version_upgrade_cluster(cluster_id)
            response = verify_cluster_changes(cluster_id)
        else:
            enable_minor_version_upgrade_instance(db_instance_id)
            response = verify_instance_changes(db_instance_id)
    else:
        enable_minor_version_upgrade_instance(db_instance_id)
        response = verify_instance_changes(db_instance_id)

    if response is True:
        return {"AutoMinorVersionUpgrade": response}

    raise RuntimeError(
        f"ASR Remediation failed - {db_instance_id} did not have enable auto minor version upgrades enabled."
    )


def multi_az_check(cluster_id):
    """
    Checks to see if the cluster is Multi-AZ. Instances within clusters that match this check are not able to be modified.
    """

    rds = connect_to_rds()
    try:
        found_cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        cluster_info = found_cluster["DBClusters"][0]
    except Exception as e:
        exit(f"Failed to get information about the cluster: {cluster_id}.  Error: {e}")

    return (cluster_info["MultiAZ"] is True) and (
        cluster_info["Engine"] in multi_az_cluster_engines
    )


def enable_minor_version_upgrade_cluster(cluster_id):
    """
    Enables automatic minor version upgrade for a Multi-AZ Cluster.
    """

    rds = connect_to_rds()
    try:
        rds.modify_db_cluster(
            DBClusterIdentifier=cluster_id, AutoMinorVersionUpgrade=True
        )
    except Exception as e:
        exit(f"Failed to modify the cluster: {cluster_id}. Error: {e}")


def enable_minor_version_upgrade_instance(instance_id):
    """
    Enables automatic minor version upgrade for an instance.
    """

    rds = connect_to_rds()
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=instance_id, AutoMinorVersionUpgrade=True
        )
    except Exception as e:
        exit(f"Failed to modify the instance: {instance_id}. Error: {e}")


def verify_cluster_changes(cluster_id):
    """
    Verifies automatic minor version upgrade for a Multi-AZ cluster.
    """
    rds = connect_to_rds()
    try:
        found_cluster = rds.describe_db_clusters(
            DBClusterIdentifier=cluster_id, MaxRecords=100
        )
        cluster_info = found_cluster["DBClusters"][0]

    except Exception as e:
        exit(f"Failed to verify cluster changes: {cluster_id}. Error: {e}")

    return cluster_info["AutoMinorVersionUpgrade"]


def verify_instance_changes(instance_id):
    """
    Verifies automatic minor version upgrade for an instance.
    """
    rds = connect_to_rds()
    try:
        found_instance = rds.describe_db_instances(
            DBInstanceIdentifier=instance_id, MaxRecords=100
        )
        instance_info = found_instance["DBInstances"][0]
    except Exception as e:
        exit(f"Failed to verify instance changes: {instance_id}. Error: {e}")

    return instance_info["AutoMinorVersionUpgrade"]
