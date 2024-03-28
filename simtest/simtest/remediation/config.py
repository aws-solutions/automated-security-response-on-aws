# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from botocore.exceptions import ClientError

from simtest.boto_session import get_session
from simtest.remediation.cloudtrail import delete_bucket
from simtest.remediation_test import RemediationTest


def run_setup_config(remediation, account, region):
    aws = get_session()

    print("This test enables AWS Config\n")

    if account == aws.get_account():
        print("Automatic Setup\n")
        print("===============\n")
        print("1) Disable AWS Config")
        print("2) Remove SNS Topic SO0111-SHARR-AFSBP-Config-1-AWSConfigNotification")
        print(
            f"3) Remove only the config bucket, so0111-aws-config-{region}-{account}. This tests that the remediation can use the existing access logging bucket, if you ran CloudTrail.1 before Config.1"
        )
        print("Note: Step 3 may take a while")
        input("HIT ENTER TO START")

        delete_default_config_recorder()
        delete_default_delivery_channel()
        delete_sns_topic(
            "SO0111-SHARR-AFSBP-Config-1-AWSConfigNotification", account, region
        )
        delete_bucket(f"so0111-aws-config-{region}-{account}")
    else:
        print("Manual Setup\n")
        print("===============\n")
        print("1) Disable AWS Config by disabling recording")
        print("2) Remove SNS Topic SO0111-SHARR-AFSBP-Config-1-AWSConfigNotification")
        print(
            f"3) Remove the config bucket, so0111-aws-config-{region}-{account}. This tests that the remediation can use the existing access logging bucket, if you ran CloudTrail.1 before Config.1"
        )
        print("Note: Step 3 may take a while")
        input("\nHit enter when you have completed these steps")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )

    test.run()

    print("\nVERIFICATION\n============\n")
    print(
        f"1) Config is enabled for all resources, globally, with logging to so0111-aws-config-{region}-{account}"
    )
    print(
        f"2) Bucket so0111-aws-config-{region}-{account} is encrypted and has access logging enabled"
    )
    print(
        f"3) Config data is flowing to the config bucket, so0111-aws-config-{region}-{account}"
    )


def delete_default_config_recorder():
    aws = get_session()
    cfgsvc = aws.client("config")
    try:
        cfgsvc.delete_configuration_recorder(ConfigurationRecorderName="default")
        print('Deleted AWS Config recorder "default"')
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # stream did exist but need new token, get it from exception data
        if exception_type == "NoSuchConfigurationRecorderException":
            print("Default delivery recorder does not exist...continuing")
        else:
            print(f"Unhandled client error {exception_type} deleting default recorder")
            raise
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise


def delete_default_delivery_channel():
    aws = get_session()
    cfgsvc = aws.client("config")
    try:
        cfgsvc.delete_delivery_channel(DeliveryChannelName="default")
        print('Deleted AWS Config delivery channel "default"')
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # stream did exist but need new token, get it from exception data
        if exception_type == "NoSuchDeliveryChannelException":
            print("Default delivery channel does not exist...continuing")
        else:
            print(
                f"Unhandled client error {exception_type} deleting default delivery channel"
            )
            raise
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise


def delete_sns_topic(topicname, account, region):
    aws = get_session()
    sns = aws.client("sns")
    topic_arn = f"arn:{aws.get_partition()}:sns:{region}:{account}:{topicname}"
    try:
        sns.delete_topic(TopicArn=topic_arn)
        print(f"Deleted Amazon SNS topic {topic_arn}")
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # stream did exist but need new token, get it from exception data
        if exception_type == "NotFoundException":
            print(f"{topicname} does not exist...continuing")
        else:
            print(
                f"Unhandled client error {exception_type} deleting sns topic {topicname}"
            )
            raise
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise
