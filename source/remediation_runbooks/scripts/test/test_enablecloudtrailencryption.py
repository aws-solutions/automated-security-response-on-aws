# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
import botocore.session
import EnableCloudTrailEncryption as validate
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


# =====================================================================================
# EnableCloudTrailEncryption SUCCESS
# =====================================================================================
def test_EnableCloudTrailEncryption_success(mocker):
    event = {
        "SolutionId": "SO0000",
        "SolutionVersion": "1.2.3",
        "trail": "foobarbaz",
        "trail_region": my_region,
        "exec_region": my_region,
        "kms_key_arn": f"arn:aws:kms:{my_region}:111111111111:key",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # LOGS
    ct_client = botocore.session.get_session().create_client(
        "cloudtrail", config=BOTO_CONFIG
    )
    ct_stubber = Stubber(ct_client)

    ct_stubber.add_response(
        "update_trail", {}, {"Name": event["trail"], "KmsKeyId": event["kms_key_arn"]}
    )

    ct_stubber.activate()

    mocker.patch(
        "EnableCloudTrailEncryption.connect_to_cloudtrail", return_value=ct_client
    )

    assert validate.enable_trail_encryption(event, {}) == {
        "response": {
            "message": f'Enabled KMS CMK encryption on {event["trail"]}',
            "status": "Success",
        }
    }

    ct_stubber.deactivate()
