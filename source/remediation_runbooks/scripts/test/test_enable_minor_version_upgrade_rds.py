# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the functionality of the `enable_minor_version_upgrade_rds` remediation script"""

from unittest.mock import patch

import boto3
from botocore.config import Config
from botocore.stub import Stubber
from enable_minor_version_upgrade_rds import lambda_handler


def test_enable_minor_version_upgrade_rds_cluster(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    rds = boto3.client("rds", config=BOTO_CONFIG)
    stub_rds = Stubber(rds)
    clients = {"rds": rds}

    instanceId = "database-instance"
    clusterId = "database-cluster"

    stub_rds.add_response(
        "describe_db_instances",
        getDescribedClusterInstance(),
        {"DBInstanceIdentifier": instanceId},
    )

    stub_rds.add_response(
        "describe_db_clusters",
        getDescribedMultiAZCluster(),
        {"DBClusterIdentifier": clusterId},
    )

    stub_rds.add_response(
        "modify_db_cluster",
        {},
        {"DBClusterIdentifier": clusterId, "AutoMinorVersionUpgrade": True},
    )

    stub_rds.add_response(
        "describe_db_clusters",
        getDescribedMultiAZClusterMinorVersionUpgrade(),
        {"DBClusterIdentifier": clusterId, "MaxRecords": 100},
    )

    stub_rds.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"DBInstanceIdentifier": instanceId}
        response = lambda_handler(event, {})
        assert response == {"AutoMinorVersionUpgrade": True}


def test_enable_minor_version_upgrade_rds_instance(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard", "max_attempts": 10})
    rds = boto3.client("rds", config=BOTO_CONFIG)
    stub_rds = Stubber(rds)
    clients = {"rds": rds}

    instanceId = "database-instance"

    stub_rds.add_response(
        "describe_db_instances",
        getDescribedInstance(),
        {"DBInstanceIdentifier": instanceId},
    )

    stub_rds.add_response(
        "modify_db_instance",
        {},
        {"DBInstanceIdentifier": instanceId, "AutoMinorVersionUpgrade": True},
    )

    stub_rds.add_response(
        "describe_db_instances",
        getDescribedInstanceMinorVersionUpgrade(),
        {"DBInstanceIdentifier": instanceId, "MaxRecords": 100},
    )

    stub_rds.activate()

    with patch("boto3.client", side_effect=lambda service, **_: clients[service]):
        event = {"DBInstanceIdentifier": instanceId}
        response = lambda_handler(event, {})
        assert response == {"AutoMinorVersionUpgrade": True}


def getDescribedClusterInstance():
    return {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "database-instance",
                "DBClusterIdentifier": "database-cluster",
                "DBInstanceClass": "db.r6g.2xlarge",
                "Engine": "aurora-mysql",
                "DBInstanceStatus": "available",
                "MasterUsername": "admin",
                "Endpoint": {
                    "Address": "test.amazonaws.com",
                    "Port": 321,
                    "HostedZoneId": "test",
                },
                "AllocatedStorage": 1,
                "PreferredBackupWindow": "09:05-09:35",
                "BackupRetentionPeriod": 1,
                "DBSecurityGroups": [],
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-", "Status": "active"}
                ],
                "DBParameterGroups": [
                    {
                        "DBParameterGroupName": "default.aurora-mysql5.7",
                        "ParameterApplyStatus": "in-sync",
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "DBSubnetGroup": {
                    "DBSubnetGroupName": "default-vpc-",
                    "DBSubnetGroupDescription": "Created from the RDS Management Console",
                    "VpcId": "vpc-",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1c"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1f"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1b"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1a"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1e"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1d"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                    ],
                },
                "PreferredMaintenanceWindow": "sun:07:48-sun:08:18",
                "PendingModifiedValues": {},
                "MultiAZ": False,
                "EngineVersion": "5.7.mysql_aurora.2.10.2",
                "AutoMinorVersionUpgrade": False,
                "ReadReplicaDBInstanceIdentifiers": [],
                "LicenseModel": "general-public-license",
                "OptionGroupMemberships": [
                    {"OptionGroupName": "default:aurora-mysql-5-7", "Status": "in-sync"}
                ],
                "PubliclyAccessible": False,
                "StorageType": "aurora",
                "DbInstancePort": 0,
                "StorageEncrypted": False,
                "DbiResourceId": "db-",
                "CACertificateIdentifier": "rds-ca-2019",
                "DomainMemberships": [],
                "CopyTagsToSnapshot": False,
                "MonitoringInterval": 60,
                "EnhancedMonitoringResourceArn": "",
                "MonitoringRoleArn": "",
                "PromotionTier": 1,
                "DBInstanceArn": "",
                "IAMDatabaseAuthenticationEnabled": False,
                "PerformanceInsightsEnabled": False,
                "DeletionProtection": False,
                "AssociatedRoles": [],
                "TagList": [],
                "CustomerOwnedIpEnabled": False,
                "BackupTarget": "region",
            }
        ],
        "ResponseMetadata": {
            "RequestId": "319d76ec-75e9-4030-9c4c-a5b648c0186e",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "x-amzn-requestid": "319d76ec-75e9-4030-9c4c-a5b648c0186e",
                "strict-transport-security": "max-age=31536000",
                "content-type": "text/xml",
                "content-length": "6206",
                "date": "Wed, 25 Jan 2023 22:48:55 GMT",
            },
            "RetryAttempts": 0,
        },
    }


def getDescribedInstanceMinorVersionUpgrade():
    return {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "database-instance",
                "DBInstanceClass": "db.r6g.2xlarge",
                "Engine": "aurora-mysql",
                "DBInstanceStatus": "available",
                "MasterUsername": "admin",
                "Endpoint": {
                    "Address": "test.amazonaws.com",
                    "Port": 321,
                    "HostedZoneId": "test",
                },
                "AllocatedStorage": 1,
                "PreferredBackupWindow": "09:05-09:35",
                "BackupRetentionPeriod": 1,
                "DBSecurityGroups": [],
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-", "Status": "active"}
                ],
                "DBParameterGroups": [
                    {
                        "DBParameterGroupName": "default.aurora-mysql5.7",
                        "ParameterApplyStatus": "in-sync",
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "DBSubnetGroup": {
                    "DBSubnetGroupName": "default-vpc-",
                    "DBSubnetGroupDescription": "Created from the RDS Management Console",
                    "VpcId": "vpc-",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1c"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1f"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1b"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1a"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1e"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1d"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                    ],
                },
                "PreferredMaintenanceWindow": "sun:07:48-sun:08:18",
                "PendingModifiedValues": {},
                "MultiAZ": False,
                "EngineVersion": "5.7.mysql_aurora.2.10.2",
                "AutoMinorVersionUpgrade": True,
                "ReadReplicaDBInstanceIdentifiers": [],
                "LicenseModel": "general-public-license",
                "OptionGroupMemberships": [
                    {"OptionGroupName": "default:aurora-mysql-5-7", "Status": "in-sync"}
                ],
                "PubliclyAccessible": False,
                "StorageType": "aurora",
                "DbInstancePort": 0,
                "StorageEncrypted": False,
                "DbiResourceId": "db-",
                "CACertificateIdentifier": "rds-ca-2019",
                "DomainMemberships": [],
                "CopyTagsToSnapshot": False,
                "MonitoringInterval": 60,
                "EnhancedMonitoringResourceArn": "",
                "MonitoringRoleArn": "",
                "PromotionTier": 1,
                "DBInstanceArn": "",
                "IAMDatabaseAuthenticationEnabled": False,
                "PerformanceInsightsEnabled": False,
                "DeletionProtection": False,
                "AssociatedRoles": [],
                "TagList": [],
                "CustomerOwnedIpEnabled": False,
                "BackupTarget": "region",
            }
        ],
        "ResponseMetadata": {
            "RequestId": "319d76ec-75e9-4030-9c4c-a5b648c0186e",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "x-amzn-requestid": "319d76ec-75e9-4030-9c4c-a5b648c0186e",
                "strict-transport-security": "max-age=31536000",
                "content-type": "text/xml",
                "content-length": "6206",
                "date": "Wed, 25 Jan 2023 22:48:55 GMT",
            },
            "RetryAttempts": 0,
        },
    }


def getDescribedInstance():
    return {
        "DBInstances": [
            {
                "DBInstanceIdentifier": "database-instance",
                "DBInstanceClass": "db.r6g.2xlarge",
                "Engine": "aurora-mysql",
                "DBInstanceStatus": "available",
                "MasterUsername": "admin",
                "Endpoint": {
                    "Address": "test.amazonaws.com",
                    "Port": 321,
                    "HostedZoneId": "test",
                },
                "AllocatedStorage": 1,
                "PreferredBackupWindow": "09:05-09:35",
                "BackupRetentionPeriod": 1,
                "DBSecurityGroups": [],
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-", "Status": "active"}
                ],
                "DBParameterGroups": [
                    {
                        "DBParameterGroupName": "default.aurora-mysql5.7",
                        "ParameterApplyStatus": "in-sync",
                    }
                ],
                "AvailabilityZone": "us-east-1a",
                "DBSubnetGroup": {
                    "DBSubnetGroupName": "default-vpc-",
                    "DBSubnetGroupDescription": "Created from the RDS Management Console",
                    "VpcId": "vpc-",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1c"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1f"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1b"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1a"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1e"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-",
                            "SubnetAvailabilityZone": {"Name": "us-east-1d"},
                            "SubnetOutpost": {},
                            "SubnetStatus": "Active",
                        },
                    ],
                },
                "PreferredMaintenanceWindow": "sun:07:48-sun:08:18",
                "PendingModifiedValues": {},
                "MultiAZ": False,
                "EngineVersion": "5.7.mysql_aurora.2.10.2",
                "AutoMinorVersionUpgrade": False,
                "ReadReplicaDBInstanceIdentifiers": [],
                "LicenseModel": "general-public-license",
                "OptionGroupMemberships": [
                    {"OptionGroupName": "default:aurora-mysql-5-7", "Status": "in-sync"}
                ],
                "PubliclyAccessible": False,
                "StorageType": "aurora",
                "DbInstancePort": 0,
                "StorageEncrypted": False,
                "DbiResourceId": "db-",
                "CACertificateIdentifier": "rds-ca-2019",
                "DomainMemberships": [],
                "CopyTagsToSnapshot": False,
                "MonitoringInterval": 60,
                "EnhancedMonitoringResourceArn": "",
                "MonitoringRoleArn": "",
                "PromotionTier": 1,
                "DBInstanceArn": "",
                "IAMDatabaseAuthenticationEnabled": False,
                "PerformanceInsightsEnabled": False,
                "DeletionProtection": False,
                "AssociatedRoles": [],
                "TagList": [],
                "CustomerOwnedIpEnabled": False,
                "BackupTarget": "region",
            }
        ],
        "ResponseMetadata": {
            "RequestId": "319d76ec-75e9-4030-9c4c-a5b648c0186e",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "x-amzn-requestid": "319d76ec-75e9-4030-9c4c-a5b648c0186e",
                "strict-transport-security": "max-age=31536000",
                "content-type": "text/xml",
                "content-length": "6206",
                "date": "Wed, 25 Jan 2023 22:48:55 GMT",
            },
            "RetryAttempts": 0,
        },
    }


def getDescribedMultiAZCluster():
    return {
        "DBClusters": [
            {
                "AllocatedStorage": 400,
                "AvailabilityZones": ["us-east-1a", "us-east-1d", "us-east-1f"],
                "BackupRetentionPeriod": 7,
                "DBClusterIdentifier": "database-cluster",
                "DBClusterParameterGroup": "default.postgres13",
                "DBSubnetGroup": "default-vpc-",
                "Status": "available",
                "Endpoint": "",
                "ReaderEndpoint": "",
                "MultiAZ": True,
                "Engine": "postgres",
                "EngineVersion": "13.7",
                "Port": 5432,
                "MasterUsername": "postgres",
                "PreferredBackupWindow": "08:46-09:16",
                "PreferredMaintenanceWindow": "thu:09:24-thu:09:54",
                "ReadReplicaIdentifiers": [],
                "DBClusterMembers": [
                    {
                        "DBInstanceIdentifier": "database-3-instance-1",
                        "IsClusterWriter": True,
                        "DBClusterParameterGroupStatus": "in-sync",
                        "PromotionTier": 1,
                    },
                    {
                        "DBInstanceIdentifier": "database-3-instance-2",
                        "IsClusterWriter": False,
                        "DBClusterParameterGroupStatus": "in-sync",
                        "PromotionTier": 1,
                    },
                    {
                        "DBInstanceIdentifier": "database-3-instance-3",
                        "IsClusterWriter": False,
                        "DBClusterParameterGroupStatus": "in-sync",
                        "PromotionTier": 1,
                    },
                ],
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-", "Status": "active"}
                ],
                "HostedZoneId": "",
                "StorageEncrypted": True,
                "KmsKeyId": "",
                "DbClusterResourceId": "",
                "DBClusterArn": "",
                "AssociatedRoles": [],
                "IAMDatabaseAuthenticationEnabled": False,
                "EngineMode": "provisioned",
                "DeletionProtection": False,
                "HttpEndpointEnabled": False,
                "ActivityStreamStatus": "stopped",
                "CopyTagsToSnapshot": False,
                "CrossAccountClone": False,
                "DomainMemberships": [],
                "TagList": [],
                "DBClusterInstanceClass": "db.m5d.large",
                "StorageType": "io1",
                "Iops": 3000,
                "PubliclyAccessible": False,
                "AutoMinorVersionUpgrade": False,
                "MonitoringInterval": 0,
                "PerformanceInsightsEnabled": False,
            }
        ],
        "ResponseMetadata": {
            "RequestId": "",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "x-amzn-requestid": "9",
                "strict-transport-security": "max-age=31536000",
                "content-type": "text/xml",
                "content-length": "4369",
                "date": "Wed, 25 Jan 2023 22:57:06 GMT",
            },
            "RetryAttempts": 0,
        },
    }


def getDescribedMultiAZClusterMinorVersionUpgrade():
    return {
        "DBClusters": [
            {
                "AllocatedStorage": 400,
                "AvailabilityZones": ["us-east-1a", "us-east-1d", "us-east-1f"],
                "BackupRetentionPeriod": 7,
                "DBClusterIdentifier": "database-cluster",
                "DBClusterParameterGroup": "default.postgres13",
                "DBSubnetGroup": "default-vpc-",
                "Status": "available",
                "Endpoint": "",
                "ReaderEndpoint": "",
                "MultiAZ": True,
                "Engine": "postgres",
                "EngineVersion": "13.7",
                "Port": 5432,
                "MasterUsername": "postgres",
                "PreferredBackupWindow": "08:46-09:16",
                "PreferredMaintenanceWindow": "thu:09:24-thu:09:54",
                "ReadReplicaIdentifiers": [],
                "DBClusterMembers": [
                    {
                        "DBInstanceIdentifier": "database-3-instance-1",
                        "IsClusterWriter": True,
                        "DBClusterParameterGroupStatus": "in-sync",
                        "PromotionTier": 1,
                    },
                    {
                        "DBInstanceIdentifier": "database-3-instance-2",
                        "IsClusterWriter": False,
                        "DBClusterParameterGroupStatus": "in-sync",
                        "PromotionTier": 1,
                    },
                    {
                        "DBInstanceIdentifier": "database-3-instance-3",
                        "IsClusterWriter": False,
                        "DBClusterParameterGroupStatus": "in-sync",
                        "PromotionTier": 1,
                    },
                ],
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-", "Status": "active"}
                ],
                "HostedZoneId": "",
                "StorageEncrypted": True,
                "KmsKeyId": "",
                "DbClusterResourceId": "",
                "DBClusterArn": "",
                "AssociatedRoles": [],
                "IAMDatabaseAuthenticationEnabled": False,
                "EngineMode": "provisioned",
                "DeletionProtection": False,
                "HttpEndpointEnabled": False,
                "ActivityStreamStatus": "stopped",
                "CopyTagsToSnapshot": False,
                "CrossAccountClone": False,
                "DomainMemberships": [],
                "TagList": [],
                "DBClusterInstanceClass": "db.m5d.large",
                "StorageType": "io1",
                "Iops": 3000,
                "PubliclyAccessible": False,
                "AutoMinorVersionUpgrade": True,
                "MonitoringInterval": 0,
                "PerformanceInsightsEnabled": False,
            }
        ],
        "ResponseMetadata": {
            "RequestId": "",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "x-amzn-requestid": "9",
                "strict-transport-security": "max-age=31536000",
                "content-type": "text/xml",
                "content-length": "4369",
                "date": "Wed, 25 Jan 2023 22:57:06 GMT",
            },
            "RetryAttempts": 0,
        },
    }
