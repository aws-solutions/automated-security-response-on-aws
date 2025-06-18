# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from botocore.exceptions import ClientError

from simtest.boto_session import get_session
from simtest.remediation_test import ControlTest, RemediationTest


def run_create_multi_region_cloudtrail(remediation, account, region):
    aws = get_session()
    remtest = ControlTest()
    remtest.load_json(remediation, wrap_it_in_findings=True)
    remtest.test_json["detail"]["findings"][0]["AwsAccountId"] = account
    remtest.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )
    remtest.create_finding()

    remtest.print_heading(
        f'This test creates a multi-region CloudTrail named "multi-region-cloud-trail", an S3 bucket for CloudTrail logging, and an S3 bucket for logging access to the CloudTrail bucket. If the buckets already exist the remediation should still succeed. Bucket names are so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account}\n'
    )

    if account == aws.get_account():
        instructions = [
            'Test setup will remove the CloudTrail named "multi-region-cloud-trail", if it exists already,',
            f"then the two buckets, so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account}",
            "Note: Step 2 may take a while",
        ]
        remtest.print_prep_instructions(instructions)

        input("Press enter to set up the test")

        delete_cloudtrail("multi-region-cloud-trail")
        delete_bucket(f"so0111-aws-cloudtrail-{account}")
        delete_bucket(f"so0111-access-logs-{region}-{account}")

    else:
        instructions = [
            '1) Remove the CloudTrail named "multi-region-cloud-trail", if it exists already.',
            f"2) Remove the two buckets, so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account}",
        ]
        remtest.print_prep_instructions(instructions)

    remtest.run()
    remtest.print_verification_instructions(
        "Verify that a multi-region cloudtrail was created with S3 bucket"
    )


def run_enable_cloudtrail_logfile_validation(remediation, account, region):
    print(
        "This test requires a CloudTrail in the region being tested. You can create one or use an existing trail. If you create one, deselect log file validation. This test will enable it.\n"
    )

    print("SETUP\n=====\n")
    print("1) Create a CloudTrail")
    print("\tLog File Validation should be FALSE")
    print("\tTrail must be in the same region as the test\n")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    # Alter the test data
    trail_name = input("Name of CloudTrail: ")

    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:cloudtrail:" + region + ":111111111111:trail/" + trail_name
    )

    test.run()

    print("\nVERIFICATION\n============\n")
    print(f"1) {trail_name} has log file validation enabled")


def run_make_cloudtrail_s3_bucket_private(remediation, account, region):
    print(
        "This test disables public access to a bucket. Rather than create a public bucket (which will result in an internal SEV2 ticket), use any private bucket or create a new bucket.\n"
    )

    print("SETUP\n=====\n")
    print(
        "1) Create an S3 bucket in the same region as the test. DO NOT MAKE IT PUBLIC!"
    )
    print("(the test will still set private access, even if already private)\n")

    test = RemediationTest("cis23", account)

    # Alter the test data
    bucket_name = input("Name of an S3 bucket: ")
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:s3:::" + bucket_name
    )

    test.run()


def run_log_cloudtrail_to_cloudwatch(remediation, account, region):
    print("This test creates a CloudWatch logs group for CloudTrail.\n")

    print("SETUP\n=====\n")
    print("1) Use the CloudTrail created for cis22 (or create a new one)\n")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    # Alter the test data
    trail_name = input("Name of CloudTrail: ")
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:cloudtrail:" + region + ":111111111111:trail/" + trail_name
    )

    test.run()

    print(
        "Verify that CloudWatch Logs Group CloudTrail/CIS2-4-"
        + trail_name
        + " was created in the target account.\n"
    )


def run_create_ct_access_logging(remediation, account, region):
    print("This test creates an access logging bucket the CloudTrail S3 bucket.\n")

    print("SETUP\n=====\n")
    print("1) Use the S3 bucket created for cis23 (or create a new one)\n")

    test = RemediationTest(remediation, account)

    # Alter the test data
    bucket_name = input("Name of an S3 bucket: ")
    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "arn:aws:s3:::" + bucket_name
    )

    test.run()

    print(
        "\nVerify that S3 bucket so0111-sharr-cloudtrailaccesslogs-<account>-"
        + region
        + " was created in the target account. If the bucket already existed then simply check the lambda logs for errors."
    )


def run_enable_ct_encryption(remediation, account, region):
    aws = get_session()
    print("This test enables encryption on a CloudTrail\n")

    print("Automatic Setup\n")
    print("===============\n")
    print("1) Removes KmsKeyId from the test cloudtrail")

    cloudtrail = input("CloudTrail to test with? ")

    remove_cloudtrail_encryption(cloudtrail, account)

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0][
        "Id"
    ] = f"arn:{aws.get_partition()}:cloudtrail:{region}:{account}:trail/{cloudtrail}"
    test.test_json["detail"]["findings"][0]["Resources"][0]["Details"][
        "AwsCloudTrailTrail"
    ]["HomeRegion"] = region

    test.run()

    print("\nVERIFICATION\n============\n")
    print(f"1) CloudTrail {cloudtrail} is encrypted")


def run_create_cloudtrail_multi_region_trail(remediation, account, region):
    aws = get_session()
    print("Simulate AWS FSBP CloudTrail.1 Findings\n")

    print(
        f'This test creates a multi-region CloudTrail named "multi-region-cloud-trail", an S3 bucket for CloudTrail logging, and an S3 bucket for logging access to the CloudTrail bucket. If the buckets already exist the remediation should still succeed. Bucket names are so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account}\n'
    )

    if account == aws.get_account():
        print("Automatic Setup\n")
        print("===============\n")
        print(
            '1) Remove the CloudTrail named "multi-region-cloud-trail", if it exists already.'
        )
        print(
            f"2) Remove the two buckets, so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account}"
        )
        print("Note: Step 2 may take a while")
        input("HIT ENTER TO START")

        delete_cloudtrail("multi-region-cloud-trail")
        delete_bucket(f"so0111-aws-cloudtrail-{account}")
        delete_bucket(f"so0111-access-logs-{region}-{account}")
    else:
        print("Manual Setup\n")
        print("===============\n")
        print(
            '1) Remove the CloudTrail named "multi-region-cloud-trail", if it exists already.'
        )
        print(
            f"2) Remove the two buckets, so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account}"
        )
        input("Press enter when ready...")

    test = RemediationTest(remediation, account, wrap_it_in_findings=True)

    test.test_json["detail"]["findings"][0]["Resources"][0]["Id"] = (
        "AWS::::Account:" + account
    )

    test.run()

    print("\nVERIFICATION\n============\n")
    print(
        '1) CloudTrail "multi-region-cloud-trail" was created, is encrypted, and is enabled for all regions'
    )
    print(
        f"2) Buckets so0111-access-logs-{region}-{account} and so0111-aws-cloudtrail-{account} were created"
    )
    print(
        f"3) CloudTrail log data is flowing to the so0111-aws-cloudtrail-{account} bucket"
    )
    print(
        f"4) Access logs for so0111-aws-cloudtrail-{account} bucket are delivered to so0111-access-logs-{region}-{account} bucket"
    )


def delete_cloudtrail(trailname):
    aws = get_session()
    ct = aws.client("cloudtrail")
    try:
        ct.delete_trail(Name=trailname)
        print("Deleted CloudTrail multi-region-cloud-trail")
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # stream did exist but need new token, get it from exception data
        if exception_type in "TrailNotFoundException":
            print("Trail does not exist...continuing")
        else:
            print(f"Unhandled client error {exception_type}")
            raise
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise


def remove_cloudtrail_encryption(trailname, account):
    aws = get_session()
    if account == aws.get_account():
        ct = aws.client("cloudtrail")
        try:
            ct.update_trail(Name=trailname, KmsKeyId="")
            print(f"Removed CloudTrail encryption from {trailname}")
        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            # stream did exist but need new token, get it from exception data
            if exception_type in "TrailNotFoundException":
                print("Trail does not exist")
                exit()
            else:
                print(f"Unhandled client error {exception_type}")
                raise
        except Exception as e:
            print(e)
            print("Something went wrong")
            raise
    else:
        print(f"Manually disable encryption on {trailname} in {account}")
        input("ENTER to continue...")


def delete_bucket(bucketname):
    aws = get_session()
    s3_resource = aws.resource("s3")
    s3 = aws.client("s3")
    try:
        bucket = s3_resource.Bucket(bucketname)
        bucket.objects.all().delete()
        s3.delete_bucket(Bucket=bucketname)
        print("Deleted CloudTrail multi-region-cloud-trail")
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # stream did exist but need new token, get it from exception data
        if exception_type in "NoSuchBucket":
            print(f"Bucket {bucketname} does not exist...continuing")
        else:
            print(
                f"Unhandled client error {exception_type} deleting bucket {bucketname}"
            )
            raise
    except Exception as e:
        print(e)
        print("Something went wrong")
        raise
