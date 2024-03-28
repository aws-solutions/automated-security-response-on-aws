# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
import botocore.session
import RemoveLambdaPublicAccess as remediation
from botocore.config import Config
from botocore.stub import Stubber

my_session = boto3.session.Session()
my_region = my_session.region_name


def test_success(mocker):
    event = {"FunctionName": "myPublicTestFunction"}

    get_policy_initial_response = {
        "ResponseMetadata": {
            "RequestId": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": "Tue, 27 Jul 2021 13:02:30 GMT",
                "content-type": "application/json",
                "content-length": "341",
                "connection": "keep-alive",
                "x-amzn-requestid": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            },
            "RetryAttempts": 0,
        },
        "Policy": '{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"sdfsdf","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicTestFunction"},{"Sid":"SHARRTest","Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicTestFunction"}]}',
        "RevisionId": "43f41078-ecd3-406d-b862-d770019c262c",
    }

    get_policy_after_response = {
        "ResponseMetadata": {
            "RequestId": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": "Tue, 27 Jul 2021 13:02:30 GMT",
                "content-type": "application/json",
                "content-length": "341",
                "connection": "keep-alive",
                "x-amzn-requestid": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            },
            "RetryAttempts": 0,
        },
        "Policy": '{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"sdfsdf","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicTestFunction"}]}',
        "RevisionId": "43f41078-ecd3-406d-b862-d770019c262c",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # Clients
    lambda_client = botocore.session.get_session().create_client(
        "lambda", config=BOTO_CONFIG
    )
    lambda_stubber = Stubber(lambda_client)

    lambda_stubber.add_response(
        "get_policy",
        get_policy_initial_response,
        {"FunctionName": "myPublicTestFunction"},
    )

    lambda_stubber.add_response(
        "remove_permission",
        {},
        {"FunctionName": "myPublicTestFunction", "StatementId": "SHARRTest"},
    )

    lambda_stubber.add_response(
        "get_policy",
        get_policy_after_response,
        {"FunctionName": "myPublicTestFunction"},
    )

    lambda_stubber.add_response(
        "get_policy",
        get_policy_after_response,
        {"FunctionName": "myPublicTestFunction"},
    )

    lambda_stubber.activate()

    mocker.patch(
        "RemoveLambdaPublicAccess.connect_to_lambda", return_value=lambda_client
    )

    assert remediation.remove_lambda_public_access(event, {}) is None

    lambda_stubber.deactivate()


def test_success_aws_star(mocker):
    event = {"FunctionName": "myPublicTestFunction"}

    get_policy_initial_response = {
        "ResponseMetadata": {
            "RequestId": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": "Tue, 27 Jul 2021 13:02:30 GMT",
                "content-type": "application/json",
                "content-length": "341",
                "connection": "keep-alive",
                "x-amzn-requestid": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            },
            "RetryAttempts": 0,
        },
        "Policy": '{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"sdfsdf","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicTestFunction"},{"Sid":"SHARRTest","Effect":"Allow","Principal":{"AWS":"*"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicTestFunction"}]}',
        "RevisionId": "43f41078-ecd3-406d-b862-d770019c262c",
    }

    get_policy_after_response = {
        "ResponseMetadata": {
            "RequestId": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": "Tue, 27 Jul 2021 13:02:30 GMT",
                "content-type": "application/json",
                "content-length": "341",
                "connection": "keep-alive",
                "x-amzn-requestid": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            },
            "RetryAttempts": 0,
        },
        "Policy": '{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"sdfsdf","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicTestFunction"}]}',
        "RevisionId": "43f41078-ecd3-406d-b862-d770019c262c",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # Clients
    lambda_client = botocore.session.get_session().create_client(
        "lambda", config=BOTO_CONFIG
    )
    lambda_stubber = Stubber(lambda_client)

    lambda_stubber.add_response(
        "get_policy",
        get_policy_initial_response,
        {"FunctionName": "myPublicTestFunction"},
    )

    lambda_stubber.add_response(
        "remove_permission",
        {},
        {"FunctionName": "myPublicTestFunction", "StatementId": "SHARRTest"},
    )

    lambda_stubber.add_response(
        "get_policy",
        get_policy_after_response,
        {"FunctionName": "myPublicTestFunction"},
    )

    lambda_stubber.add_response(
        "get_policy",
        get_policy_after_response,
        {"FunctionName": "myPublicTestFunction"},
    )

    lambda_stubber.activate()

    mocker.patch(
        "RemoveLambdaPublicAccess.connect_to_lambda", return_value=lambda_client
    )

    assert remediation.remove_lambda_public_access(event, {}) is None

    lambda_stubber.deactivate()


def test_success_s3_statement(mocker):
    event = {"FunctionName": "myPublicS3TestFunction"}

    get_policy_initial_response = {
        "ResponseMetadata": {
            "RequestId": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": "Tue, 27 Jul 2021 13:02:30 GMT",
                "content-type": "application/json",
                "content-length": "341",
                "connection": "keep-alive",
                "x-amzn-requestid": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            },
            "RetryAttempts": 0,
        },
        "Policy": '{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"sdfsdf","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicS3TestFunction"},{"Sid": "lambda-allow-s3-my-function-test","Effect": "Allow","Principal": {"Service": "s3.amazonaws.com"},"Action": "lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicS3TestFunction", "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::my-bucket"}},"RevisionId":"43f41078-ecd3-406d-b862-d770019c262c"}]}',
    }

    get_policy_after_response = {
        "ResponseMetadata": {
            "RequestId": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {
                "date": "Tue, 27 Jul 2021 13:02:30 GMT",
                "content-type": "application/json",
                "content-length": "341",
                "connection": "keep-alive",
                "x-amzn-requestid": "8a2cc603-ba43-467d-be12-a4f7a28f93bf",
            },
            "RetryAttempts": 0,
        },
        "Policy": '{"Version":"2012-10-17","Id":"default","Statement":[{"Sid":"sdfsdf","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"lambda:InvokeFunction","Resource":"arn:aws:lambda:us-east-1:111111111111:function:myPublicS3TestFunction"}]}',
        "RevisionId": "43f41078-ecd3-406d-b862-d770019c262c",
    }

    BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=my_region)

    # Clients
    lambda_client = botocore.session.get_session().create_client(
        "lambda", config=BOTO_CONFIG
    )
    lambda_stubber = Stubber(lambda_client)

    lambda_stubber.add_response(
        "get_policy",
        get_policy_initial_response,
        {"FunctionName": "myPublicS3TestFunction"},
    )

    lambda_stubber.add_response(
        "remove_permission",
        {},
        {
            "FunctionName": "myPublicS3TestFunction",
            "StatementId": "lambda-allow-s3-my-function-test",
        },
    )

    lambda_stubber.add_response(
        "get_policy",
        get_policy_after_response,
        {"FunctionName": "myPublicS3TestFunction"},
    )

    lambda_stubber.add_response(
        "get_policy",
        get_policy_after_response,
        {"FunctionName": "myPublicS3TestFunction"},
    )

    lambda_stubber.activate()

    mocker.patch(
        "RemoveLambdaPublicAccess.connect_to_lambda", return_value=lambda_client
    )

    assert remediation.remove_lambda_public_access(event, {}) is None

    lambda_stubber.deactivate()
