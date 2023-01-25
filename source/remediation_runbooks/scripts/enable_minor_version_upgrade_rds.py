# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(
    retries = {
            'mode': 'standard',
            'max_attempts': 10
        }
    )

multiAZClusterEngines = ["mysql","postgres"]

def connect_to_rds():
    return boto3.client('rds', config=boto_config)

def lambda_handler(event, _):
    """
     Enable auto minor version upgrades on an instance or a Multi-AZ Cluster
 
     `event` should have the following keys and values:
     `DBInstanceIdentifier`: The identifier of the database instance that is to be modified.
 
     `context` is ignored
    """
    dbInstanceID = event["DBInstanceIdentifier"]

    rds = connect_to_rds()

    foundInstance = rds.describe_db_instances(DBInstanceIdentifier=dbInstanceID)

    instanceInfo = foundInstance['DBInstances'][0]

    response = False

    if ("DBClusterIdentifier" in instanceInfo.keys()):
        if (multi_az_check(instanceInfo["DBClusterIdentifier"])):
            clusterID = instanceInfo["DBClusterIdentifier"]
            enable_minor_version_upgrade_cluster(clusterID)
            response = verify_cluster_changes(clusterID)
        else:
            enable_minor_version_upgrade_instance(dbInstanceID)
            response = verify_instance_changes(dbInstanceID)
    else:
        enable_minor_version_upgrade_instance(dbInstanceID)
        response = verify_instance_changes(dbInstanceID)
        
    if response == True:
        return {
            "AutoMinorVersionUpgrade": response
        }
    
    raise Exception(f'ASR Remediation failed - {dbInstanceID} did not have enable auto minor version upgrades enabled.')

def multi_az_check(clusterID):
    """
    Checks to see if the cluster is Multi-AZ. Instances within clusters that match this check are not able to be modified.
    """  

    rds = connect_to_rds()
    try:
        foundCluster = rds.describe_db_clusters(DBClusterIdentifier=clusterID)
        clusterInfo = foundCluster['DBCluster']
    except Exception as e:
        exit(f'Failed to get information about the cluster: {clusterID} ')

    return ((clusterInfo["MultiAZ"] == True) and (clusterInfo["Engine"] in multiAZClusterEngines))


def enable_minor_version_upgrade_cluster(clusterID):
    """
    Enables automatic minor version upgrade for a Multi-AZ Cluster.
    """ 

    rds = connect_to_rds()
    try:
        rds.modify_db_cluster(DBClusterIdentifier=clusterID,AutoMinorVersionUpgrade=True)
    except Exception as e:
        exit(f'Failed to modify the cluster: {clusterID}. Error: {e}')

def enable_minor_version_upgrade_instance(instanceID):
    """
    Enables automatic minor version upgrade for an instance.
    """ 

    rds = connect_to_rds()
    try:
        rds.modify_db_instance(DBInstanceIdentifier=instanceID,AutoMinorVersionUpgrade=True)
    except Exception as e:
        exit(f'Failed to modify the instance: {instanceID}. Error: {e}')

def verify_cluster_changes(clusterID):
    """
    Verifies automatic minor version upgrade for a Multi-AZ cluster.
    """ 
    rds = connect_to_rds()
    try:
        foundCluster = rds.describe_db_clusters(DBClusterIdentifier=clusterID, MaxRecords=100)
        clusterInfo = foundCluster['DBCluster']

    except Exception as e:
        exit(f'Failed to verify cluster changes: {clusterID}. Error: {e}')

    return clusterInfo['AutoMinorVersionUpgrade']
        
def verify_instance_changes(instanceID):
    """
    Verifies automatic minor version upgrade for an instance.
    """ 
    rds = connect_to_rds()
    try:
        foundInstance = rds.describe_db_instances(DBInstanceIdentifier=instanceID, MaxRecords=100)
        instanceInfo = foundInstance['DBInstances'][0]
    except Exception as e:

        exit(f'Failed to verify instance changes: {instanceID}. Error: {e}')

    return instanceInfo['AutoMinorVersionUpgrade'] 

