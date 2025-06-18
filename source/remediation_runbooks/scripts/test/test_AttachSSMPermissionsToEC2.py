# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re

import AttachSSMPermissionsToEC2 as remediation
import boto3
import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_aws

BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name="us-east-1")
TEST_INSTANCE_PROFILE_NAME = "test-instance-profile"
GENERIC_TEST_IAM_ROLE_NAME = "test-iam-role"
SSM_IAM_ROLE_NAME = "SO0111-AttachSSMPermissionsToEC2-RemediationRole"
SSM_INSTANCE_PROFILE_NAME = "SO0111-AttachSSMPermissionsToEC2-InstanceProfile"
SSM_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


def setup():
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)
    iam_client = boto3.client("iam", config=BOTO_CONFIG)

    # Create IAM role for testing
    create_test_iam_role(SSM_IAM_ROLE_NAME)
    add_ssm_permissions_to_role(SSM_IAM_ROLE_NAME)

    # Create instance for testing
    response = ec2_client.run_instances(
        ImageId="ami-abc12345",
        InstanceType="t2.micro",
        MaxCount=1,
        MinCount=1,
    )
    instance_id = response["Instances"][0]["InstanceId"]

    # Create Instance Profile for testing
    iam_client.create_instance_profile(
        InstanceProfileName=SSM_INSTANCE_PROFILE_NAME,
    )

    # Attach role to profile
    iam_client.add_role_to_instance_profile(
        InstanceProfileName=SSM_INSTANCE_PROFILE_NAME,
        RoleName=SSM_IAM_ROLE_NAME,
    )

    return (
        "arn:aws:ec2:us-east-1:" + response["OwnerId"] + ":instance/" + instance_id,
        instance_id,
    )


def create_test_iam_role(name):
    iam_client = boto3.client("iam", config=BOTO_CONFIG)
    response = iam_client.create_role(RoleName=name, AssumeRolePolicyDocument="{}")
    return response["Role"]["RoleName"]


def setup_instance_profile(profile_name, instance_id):
    iam_client = boto3.client("iam", config=BOTO_CONFIG)
    ec2_client = boto3.client("ec2", config=BOTO_CONFIG)

    iam_client.create_instance_profile(
        InstanceProfileName=profile_name,
    )

    ec2_client.associate_iam_instance_profile(
        IamInstanceProfile={"Name": profile_name}, InstanceId=instance_id
    )


def add_ssm_permissions_to_role(role_name):
    iam_client = boto3.client("iam", config=BOTO_CONFIG)
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=SSM_MANAGED_POLICY_ARN,
    )


def get_instance_profile_name(instance_id):
    client = boto3.client("ec2", config=BOTO_CONFIG)
    response = client.describe_iam_instance_profile_associations(
        Filters=[
            {
                "Name": "instance-id",
                "Values": [instance_id],
            }
        ]
    )
    return response["IamInstanceProfileAssociations"][0]["IamInstanceProfile"][
        "Arn"
    ].split("/")[1]


def get_iam_role_from_instance_profile(instance_profile_name):
    client = boto3.client("iam", config=BOTO_CONFIG)
    response = client.get_instance_profile(InstanceProfileName=instance_profile_name)
    return response["InstanceProfile"]["Roles"][0]["RoleName"]


def iam_role_has_ssm_managed_policy(role_name):
    client = boto3.client("iam", config=BOTO_CONFIG)
    response = client.list_attached_role_policies(RoleName=role_name)
    for policy in response["AttachedPolicies"]:
        if policy["PolicyName"] == "AmazonSSMManagedInstanceCore":
            return True
    return False


def instance_has_ssm_permissions(instance_id):
    instance_profile_name = get_instance_profile_name(instance_id)
    role_name = get_iam_role_from_instance_profile(instance_profile_name)
    return iam_role_has_ssm_managed_policy(role_name)


def setup_client_stubber(client, method, mocker):
    client = botocore.session.get_session().create_client(client, config=BOTO_CONFIG)
    stubber = Stubber(client)

    stubber.add_client_error(
        method,
        service_error_code="ServiceException",
        service_message="Error",
    )
    mocker.patch("AttachSSMPermissionsToEC2.connect_to_iam", return_value=client)
    return stubber


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_without_existing_instance_profile():
    instance_arn, instance_id = setup()
    remediation.lambda_handler(
        {
            "InstanceArn": instance_arn,
            "RemediationRole": SSM_IAM_ROLE_NAME,
            "InstanceProfile": SSM_INSTANCE_PROFILE_NAME,
        },
        None,
    )
    assert instance_has_ssm_permissions(instance_id)


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_with_existing_instance_profile():
    instance_arn, instance_id = setup()
    setup_instance_profile(TEST_INSTANCE_PROFILE_NAME, instance_id)

    remediation.lambda_handler(
        {
            "InstanceArn": instance_arn,
            "RemediationRole": SSM_IAM_ROLE_NAME,
            "InstanceProfile": SSM_INSTANCE_PROFILE_NAME,
        },
        None,
    )

    assert instance_has_ssm_permissions(instance_id)
    profile_name = get_instance_profile_name(instance_id)
    assert profile_name == TEST_INSTANCE_PROFILE_NAME


@mock_aws(config={"iam": {"load_aws_managed_policies": True}})
def test_with_existing_instance_profile_and_role():
    instance_arn, instance_id = setup()
    setup_instance_profile(TEST_INSTANCE_PROFILE_NAME, instance_id)
    role_name = create_test_iam_role(GENERIC_TEST_IAM_ROLE_NAME)

    iam_client = boto3.client("iam", config=BOTO_CONFIG)
    iam_client.add_role_to_instance_profile(
        InstanceProfileName=TEST_INSTANCE_PROFILE_NAME,
        RoleName=role_name,
    )

    remediation.lambda_handler(
        {
            "InstanceArn": instance_arn,
            "RemediationRole": SSM_IAM_ROLE_NAME,
            "InstanceProfile": SSM_INSTANCE_PROFILE_NAME,
        },
        None,
    )

    assert instance_has_ssm_permissions(instance_id)
    profile_name = get_instance_profile_name(instance_id)
    assert profile_name == TEST_INSTANCE_PROFILE_NAME
    iam_role_name = get_iam_role_from_instance_profile(profile_name)
    assert iam_role_name == GENERIC_TEST_IAM_ROLE_NAME


def test_invalid_event():
    with pytest.raises(Exception) as e:
        remediation.lambda_handler(
            {
                "SomeValue": "test_value",
            },
            None,
        )
    assert re.match(r"Encountered error remediating SSM.1: ", str(e.value))


def test_attach_instance_profile_error(mocker):
    ec2_stubber = setup_client_stubber("ec2", "associate_iam_instance_profile", mocker)

    ec2_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.attach_instance_profile("test-instance-profile", "test-instance-id")

    assert re.match(
        r"Failed to associate instance profile test-instance-profile with instance test-instance-id:",
        str(e.value),
    )
    ec2_stubber.deactivate()


def test_get_iam_role_from_instance_profile_error(mocker):
    iam_stubber = setup_client_stubber("iam", "get_instance_profile", mocker)

    iam_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.get_iam_role_from_instance_profile("test-instance-profile")

    assert re.match(
        r"Failed to get role from instance profile test-instance-profile:", str(e.value)
    )
    iam_stubber.deactivate()


def test_get_existing_instance_profile_error(mocker):
    ec2_stubber = setup_client_stubber(
        "ec2", "describe_iam_instance_profile_associations", mocker
    )

    ec2_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.get_existing_instance_profile("test-instance-id")

    assert re.match(
        r"Failed to describe profile attached to instance test-instance-id:",
        str(e.value),
    )
    ec2_stubber.deactivate()


def test_setup_instance_profile_error(mocker):
    iam_stubber = setup_client_stubber("iam", "add_role_to_instance_profile", mocker)

    iam_stubber.activate()
    with pytest.raises(Exception) as e:
        remediation.setup_instance_profile("test-role-name", "test-instance-profile")

    assert re.match(
        r"Failed to add role test-role-name to instance profile test-instance-profile:",
        str(e.value),
    )
    iam_stubber.deactivate()
