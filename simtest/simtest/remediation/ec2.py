# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from simtest.boto_session import get_session
from simtest.remediation_test import RemediationTest


def run_remove_public_ec2_snaps(remediation, account, region):
    aws = get_session()
    print("This test removes public permissions from an EC2 Snapshot\n")

    print("WARNING: This test may result in a Sev 2!\n")
    input("Press ENTER to confirm that you read the warning.")

    snapshot_id = None
    if account == aws.get_account():
        print("Automatic Setup\n")
        print("===============\n")
        print(
            "1) Select a snapshot from your test account. Snapshot must not have sensitive, customer, or production data!"
        )
        input("HIT ENTER TO START")

        snapshot_id = input("Snapshot Id: ")
        ec2 = aws.client("ec2")

        try:
            ec2.modify_snapshot_attribute(
                Attribute="CreateVolumePermission",
                CreateVolumePermission={"Add": [{"Group": "all"}]},
                SnapshotId=snapshot_id,
            )
            print(f"Snapshot {snapshot_id} permissions set to PUBLIC")
        except Exception as e:
            print(e)
            print("Something went wrong")
    else:
        print("Manual Setup\n")
        print("===============\n")
        print(
            "1) Select a snapshot from your test account. Snapshot must not have sensitive, customer, or production data!"
        )
        print("2) Change the snapshot permissions to make it public.")
        input("Press enter when ready...")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Region"] = region
    # test.test_json['detail']['findings'][0]['testmode'] = True

    test.run()

    print("\nVERIFICATION\n============\n")
    print(f"1) {snapshot_id} is no longer public")


def run_close_default_sg(remediation, account, region):
    print(
        "This test removes open ports in- and outbound from the security group in the finding. You will need to create a security group in the AWS console.\n"
    )

    print("Manual Setup\n")
    print("============\n")
    print("Please do the following")
    print(
        '1) Create (or select) a default Security Group in your test account. It must be named "default". Allow all inbound and outbound traffic from/to anywhere. Enter the Security Group Id below.'
    )
    sg_id = input("Security Group Id?: ")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0][
        "Id"
    ] = f"arn:aws:ec2:{region}:{account}:security-group/{sg_id}"
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsEc2SecurityGroup"
    ]["GroupId"] = sg_id

    test.run()

    print("\nVERIFICATION\n============\n")
    print(f"1) {sg_id} both inbound and outbound rules are removed")


def run_disable_public_access_for_security_group(remediation, account, region):
    print("Simulate cis4142 Findings\n")
    print("This test closes inbound ports on a Security Group.\n")

    print("SETUP\n=====\n")
    print("1) Create a Security Group")
    print("2) Configure it to allow open inbound access to ports 22 and 3389\n")

    test = RemediationTest(remediation, account)

    # Alter the test data
    sg_id = input("Security Group: ")
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:ec2:us-east-2:111111111111:security-group/" + sg_id
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsEc2SecurityGroup"
    ]["GroupId"] = sg_id
    test.run()

    print(
        "\nThis remediation uses SSM Automation Documents on the target account. Verify that there are no lambda errors."
    )


def run_remove_vpc_default_security_group_rules(remediation, account, region):
    print("Simulate cis43 Findings\n")

    print("This test closes access inbound and outbound for a Securty Group.\n")

    print("SETUP\n=====\n")
    print("1) Create a Security Group")
    print(
        "2) Configure it to allow open inbound and outbound access: all protocols from/to anywhere.\n"
    )

    test = RemediationTest(remediation, account)

    # Alter the test data
    sg_id = input("Security Group: ")
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:ec2:us-east-2:111111111111:security-group/" + sg_id
    )
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsEc2SecurityGroup"
    ]["GroupId"] = sg_id

    test.run()


def run_enable_ebs_encryption_by_default(remediation, account, region):
    aws = get_session()
    print("Simulate AWS FSBP EC2.7 Findings\n")

    print("This test enables EBS encryption by default.\n")
    if account == aws.get_account():
        print("Automatic Setup\n")
        print("============\n")
        print("1) Disables EBS encryption by default.")

        input("HIT ENTER TO START")

        disable_ebs_encryption_by_default()
    else:
        print("Manual Setup\n")
        print("============\n")
        print("1) Disable EBS encryption by default in the target account:")
        print("   EC2 Dashboard->Account Attributes->EBS Encryption")
        input("Press enter when ready...")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )

    test.run()

    print("\nVERIFICATION\n============\n")
    print(
        "1) In EC2 Dashboard, click EBS Encryption under Account Attributes and confirm that it is enabled."
    )


def disable_ebs_encryption_by_default():
    aws = get_session()
    ec2 = aws.client("ec2")
    try:
        ec2.disable_ebs_encryption_by_default()
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise
