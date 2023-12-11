import boto3
import botocore.session
from botocore.config import Config
from botocore.stub import Stubber
from moto import mock_s3
from pytest_mock import mocker
from pytest import raises

import EnableServerAccessLoggingS3 as script


def get_region() -> str:
    my_session = boto3.session.Session()
    return my_session.region_name


def event():
    return {
        "bucket": "mahbukkit",
        "targetbucket": "so0111-server-access-logs",
        "account": "111111111111",
        "region": get_region(),
    }


@mock_s3
def test_enable_bucket_logging(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)

    bucket_name = event["bucket"]
    target_bucket_name = event["bucket"] + "-" + event["region"] + "-" + event["account"]

    kwargs = {
        "Bucket": target_bucket_name,
    }
    if event["region"] != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {
            "LocationConstraint": event["region"]
        }
    s3_stubber.add_response("create_bucket", {}, kwargs)
    s3_stubber.add_response(
        "put_bucket_logging",
        {},
        {
            "Bucket": bucket_name,
            "BucketLoggingStatus":{
                'LoggingEnabled': {
                    'TargetBucket': target_bucket_name,
                    'TargetPrefix': bucket_name + '/logs/'
                }
            }
        },
    )
    s3_stubber.activate()
    mocker.patch(
        "EnableServerAccessLoggingS3.connect_to_s3", return_value=s3
    )
    script.enable_server_access_logging(event(), {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()

    
def test_bucket_already_exists(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)

    s3_stubber.add_client_error("create_bucket", "BucketAlreadyExists")

    s3_stubber.activate()
    mocker.patch(
        "EnableServerAccessLoggingS3.connect_to_s3", return_value=s3
    )
    with raises(SystemExit):
        script.enable_server_access_logging(event(), {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()


def test_bucket_already_owned_by_you(mocker):
    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=get_region())
    s3 = botocore.session.get_session().create_client("s3", config=BOTO_CONFIG)

    s3_stubber = Stubber(s3)

    s3_stubber.add_client_error("create_bucket", "BucketAlreadyOwnedByYou")

    s3_stubber.activate()
    mocker.patch(
        "EnableServerAccessLoggingS3.connect_to_s3", return_value=s3
    )
    script.enable_server_access_logging(event(), {})
    s3_stubber.assert_no_pending_responses()
    s3_stubber.deactivate()