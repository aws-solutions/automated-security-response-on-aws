# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.remediation_test import RemediationTest


def run_make_rds_snapshot_private(remediation, account, region):
    print("This test makes an RDS snapshot private.\n")

    print("WARNING: This test may result in a Sev 2!\n")
    input("Press ENTER to confirm that you read the warning.")

    print("Manual Setup")
    print("============\n")
    print("This test requires an unencrypted RDS database")
    print(
        "1) Create an unencrypted RDS snapshot from a cluster with NO CUSTOMER OR SENSITIVE DATA."
    )
    print("2) Make the snapshot public (Actions->Share Snapshot)")
    public_snapshot = input("\nName of public snapshot?: ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0][
        "Id"
    ] = f"arn:aws:rds:{region}:{account}:cluster-snapshot:{public_snapshot}"

    test.run()

    print("\nVERIFICATION\n============\n")
    print("1) In RDS, verify that the snapshot is not public.")


def run_enable_enhanced_monitoring_on_rds_instance(remediation, account, region):
    print("Simulate AWS FSBP RDS.6 Findings\n")

    print("This test enables enhanced monitoring on an RDS cluster.\n")

    print("Manual Setup")
    print("============\n")
    print(
        "1) Select an RDS database cluster to test with. Be sure to deselect Enable Encryption under Additional Configuration when you create the cluster to test with."
    )
    print(
        "2) Disable enhanced monitoring for a database instance (database->Modify->Advanced configuration->Monitoring"
    )
    print(
        "3) Get the Resource ID from the database (not cluster) Resource ID on the Configuration Tab"
    )
    dbi_resourceid = input("\nResource ID? (db-xxxxxxxxxxx): ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsRdsDbInstance"
    ]["DbiResourceId"] = dbi_resourceid

    test.run()

    print("\nVERIFICATION\n============\n")
    print("1) In RDS, verify that enhanced monitoring is enabled.")


def run_enable_rds_cluster_deletion_protection(remediation, account, region):
    print("Simulate AWS FSBP RDS.7 Findings\n")

    print("This test enables termination protection.\n")

    print("Manual Setup")
    print("============\n")
    print("1) Select an RDS cluster to test with.")
    print(
        "2) Disable Termination Protection for the RDS cluster (Modify button, Deletion protection)"
    )
    print(
        "3) Get the Cluster Resource ID from the cluster (not database) Configuration Tab"
    )
    cluster_resourceid = input("\nCluster Resource Id? (cluster-xxxxxxxxxxxx): ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsRdsDbCluster"
    ]["DbClusterResourceId"] = cluster_resourceid

    test.run()

    print("\nVERIFICATION\n============\n")
    print("1) In RDS, verify that termination protection is enabled.")
