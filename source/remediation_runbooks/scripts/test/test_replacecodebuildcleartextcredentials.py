# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

import boto3.session
import botocore.session
import pytest
import ReplaceCodeBuildClearTextCredentials as remediation
from botocore.config import Config
from botocore.stub import ANY, Stubber


def get_region() -> str:
    my_session = boto3.session.Session()
    return my_session.region_name


def get_config() -> Config:
    return Config(retries={"mode": "standard"}, region_name=get_region())


class Case:
    def __init__(self, env_vars):
        self._env_vars = env_vars
        self._project_name = "invoke-codebuild-2"
        self._service_role = f"codebuild-{ self._project_name }-service-role"
        self._policy_name = (
            f"CodeBuildSSMParameterPolicy-{ self._project_name }-{ get_region() }"
        )
        self._policy_arn = f"arn:aws:iam::111111111111:policy/{ self._policy_name }"
        self._policy_modtime = datetime.now()

    def event(self):
        return {
            "ProjectInfo": {
                "name": self._project_name,
                "arn": f"arn:aws:codebuild:{get_region()}:111111111111:project/{ self._project_name }",
                "source": {
                    "type": "NO_SOURCE",
                    "gitCloneDepth": 1,
                    "buildspec": 'version: 0.2\n\nphases:\n  build:\n    commands:\n       - echo "Hello world!"\n',
                    "insecureSsl": False,
                },
                "secondarySources": [],
                "secondarySourceVersions": [],
                "artifacts": {"type": "NO_ARTIFACTS"},
                "secondaryArtifacts": [],
                "cache": {"type": "NO_CACHE"},
                "environment": {
                    "type": "ARM_CONTAINER",
                    "image": "aws/codebuild/amazonlinux2-aarch64-standard:2.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                    "environmentVariables": self._env_vars,
                    "privilegedMode": False,
                    "imagePullCredentialsType": "CODEBUILD",
                },
                "serviceRole": f"arn:aws:iam::111111111111:role/service-role/{ self._service_role }",
                "timeoutInMinutes": 60,
                "queuedTimeoutInMinutes": 480,
                "encryptionKey": f"arn:aws:kms:{get_region()}:111111111111:alias/aws/s3",
                "tags": [],
                "created": "2022-01-28T21:59:12.932000+00:00",
                "lastModified": "2022-02-02T19:16:05.722000+00:00",
                "badge": {"badgeEnabled": False},
                "logsConfig": {
                    "cloudWatchLogs": {"status": "DISABLED"},
                    "s3Logs": {"status": "DISABLED", "encryptionDisabled": False},
                },
                "fileSystemLocations": [],
                "projectVisibility": "PRIVATE",
            }
        }

    def parameter_name(self, env_var_name):
        return f"{ remediation.get_project_ssm_namespace(self._project_name) }/env/{ env_var_name }"

    def policy(self):
        return {
            "Policy": {
                "PolicyName": self._policy_name,
                "PolicyId": "1234567812345678",
                "Arn": self._policy_arn,
                "Path": "/",
                "DefaultVersionId": "",
                "AttachmentCount": 0,
                "PermissionsBoundaryUsageCount": 0,
                "IsAttachable": True,
                "Description": "",
                "CreateDate": self._policy_modtime,
                "UpdateDate": self._policy_modtime,
                "Tags": [],
            }
        }

    def policy_serialized(self):
        policy = self.policy()
        policy["Policy"]["CreateDate"] = policy["Policy"]["CreateDate"].isoformat()
        policy["Policy"]["UpdateDate"] = policy["Policy"]["UpdateDate"].isoformat()
        return policy

    def attach_params(self):
        return {"PolicyArn": self._policy_arn, "RoleName": self._service_role}


def successful_parameter_response():
    return {"Tier": "Standard", "Version": 1}


def test_success(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"}
    ]

    test_case = Case(env_vars)

    expected_env_vars = [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "type": "PARAMETER_STORE",
            "value": test_case.parameter_name(env_vars[0]["name"]),
        }
    ]

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_response(
        "put_parameter",
        successful_parameter_response(),
        {
            "Name": test_case.parameter_name(env_vars[0]["name"]),
            "Description": ANY,
            "Value": env_vars[0]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_response("create_policy", test_case.policy())

    iam_stubber.add_response("attach_role_policy", {}, test_case.attach_params())

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    project_env = test_case.event()["ProjectInfo"]["environment"]
    project_env["environmentVariables"] = expected_env_vars
    successful_response = {
        "AttachResponse": {},
        "Parameters": [successful_parameter_response()],
        "Policy": test_case.policy_serialized(),
        "UpdatedProjectEnv": project_env,
    }

    assert remediation.replace_credentials(test_case.event(), {}) == successful_response

    ssm_stubber.deactivate()
    iam_stubber.deactivate()


def test_multiple_params(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"},
        {"name": "AWS_SECRET_ACCESS_KEY", "value": "test_value_2", "type": "PLAINTEXT"},
        {
            "name": "AN_ACCEPTABLE_PARAMETER",
            "value": "test_value_3",
            "type": "PLAINTEXT",
        },
    ]

    test_case = Case(env_vars)

    expected_env_vars = [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "type": "PARAMETER_STORE",
            "value": test_case.parameter_name(env_vars[0]["name"]),
        },
        {
            "name": "AWS_SECRET_ACCESS_KEY",
            "type": "PARAMETER_STORE",
            "value": test_case.parameter_name(env_vars[1]["name"]),
        },
        {
            "name": "AN_ACCEPTABLE_PARAMETER",
            "value": "test_value_3",
            "type": "PLAINTEXT",
        },
    ]

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    for env_var in env_vars[0:2]:
        ssm_stubber.add_response(
            "put_parameter",
            successful_parameter_response(),
            {
                "Name": test_case.parameter_name(env_var["name"]),
                "Description": ANY,
                "Value": env_var["value"],
                "Type": "SecureString",
                "Overwrite": False,
                "DataType": "text",
            },
        )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_response("create_policy", test_case.policy())

    iam_stubber.add_response("attach_role_policy", {}, test_case.attach_params())

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    project_env = test_case.event()["ProjectInfo"]["environment"]
    project_env["environmentVariables"] = expected_env_vars
    successful_response = {
        "AttachResponse": {},
        "Parameters": [successful_parameter_response()] * 2,
        "Policy": test_case.policy_serialized(),
        "UpdatedProjectEnv": project_env,
    }

    assert remediation.replace_credentials(test_case.event(), {}) == successful_response

    ssm_stubber.deactivate()
    iam_stubber.deactivate()


def test_param_exists(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"}
    ]

    test_case = Case(env_vars)

    expected_env_vars = [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "type": "PARAMETER_STORE",
            "value": test_case.parameter_name(env_vars[0]["name"]),
        }
    ]

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_client_error(
        "put_parameter",
        "ParameterAlreadyExists",
        expected_params={
            "Name": test_case.parameter_name(env_vars[0]["name"]),
            "Description": ANY,
            "Value": env_vars[0]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_response("create_policy", test_case.policy())

    iam_stubber.add_response("attach_role_policy", {}, test_case.attach_params())

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    project_env = test_case.event()["ProjectInfo"]["environment"]
    project_env["environmentVariables"] = expected_env_vars
    successful_response = {
        "AttachResponse": {},
        "Parameters": [None],
        "Policy": test_case.policy_serialized(),
        "UpdatedProjectEnv": project_env,
    }

    assert remediation.replace_credentials(test_case.event(), {}) == successful_response

    ssm_stubber.deactivate()
    iam_stubber.deactivate()


def test_policy_exists(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"}
    ]

    test_case = Case(env_vars)

    expected_env_vars = [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "type": "PARAMETER_STORE",
            "value": test_case.parameter_name(env_vars[0]["name"]),
        }
    ]

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_response(
        "put_parameter",
        successful_parameter_response(),
        {
            "Name": test_case.parameter_name(env_vars[0]["name"]),
            "Description": ANY,
            "Value": env_vars[0]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_client_error("create_policy", "EntityAlreadyExists")

    iam_stubber.add_response("attach_role_policy", {}, test_case.attach_params())

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    project_env = test_case.event()["ProjectInfo"]["environment"]
    project_env["environmentVariables"] = expected_env_vars
    successful_response = {
        "AttachResponse": {},
        "Parameters": [successful_parameter_response()],
        "Policy": {"Policy": {"Arn": test_case.policy_serialized()["Policy"]["Arn"]}},
        "UpdatedProjectEnv": project_env,
    }

    assert remediation.replace_credentials(test_case.event(), {}) == successful_response

    ssm_stubber.deactivate()
    iam_stubber.deactivate()


def test_new_param(mocker):
    env_vars = [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "value": "an_existing_parameter",
            "type": "PARAMETER_STORE",
        },
        {"name": "AWS_SECRET_ACCESS_KEY", "value": "test_value_2", "type": "PLAINTEXT"},
    ]

    test_case = Case(env_vars)

    expected_env_vars = [
        {
            "name": "AWS_ACCESS_KEY_ID",
            "type": "PARAMETER_STORE",
            "value": "an_existing_parameter",
        },
        {
            "name": "AWS_SECRET_ACCESS_KEY",
            "type": "PARAMETER_STORE",
            "value": test_case.parameter_name(env_vars[1]["name"]),
        },
    ]

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_response(
        "put_parameter",
        successful_parameter_response(),
        {
            "Name": test_case.parameter_name(env_vars[1]["name"]),
            "Description": ANY,
            "Value": env_vars[1]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_response("create_policy", test_case.policy())

    iam_stubber.add_response("attach_role_policy", {}, test_case.attach_params())

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    project_env = test_case.event()["ProjectInfo"]["environment"]
    project_env["environmentVariables"] = expected_env_vars
    successful_response = {
        "AttachResponse": {},
        "Parameters": [successful_parameter_response()],
        "Policy": test_case.policy_serialized(),
        "UpdatedProjectEnv": project_env,
    }

    assert remediation.replace_credentials(test_case.event(), {}) == successful_response

    ssm_stubber.deactivate()
    iam_stubber.deactivate()


def test_put_parameter_fails(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"}
    ]

    test_case = Case(env_vars)

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_client_error(
        "put_parameter",
        " InternalServerError",
        http_status_code=500,
        expected_params={
            "Name": test_case.parameter_name(env_vars[0]["name"]),
            "Description": ANY,
            "Value": env_vars[0]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=None
    )

    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.replace_credentials(test_case.event(), {})
    assert wrapped_exception.type == SystemExit

    ssm_stubber.deactivate()


def test_create_policy_fails(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"}
    ]

    test_case = Case(env_vars)

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_response(
        "put_parameter",
        successful_parameter_response(),
        {
            "Name": test_case.parameter_name(env_vars[0]["name"]),
            "Description": ANY,
            "Value": env_vars[0]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_client_error(
        "create_policy", " ServiceFailure", http_status_code=500
    )

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.replace_credentials(test_case.event(), {})
    assert wrapped_exception.type == SystemExit

    ssm_stubber.deactivate()
    iam_stubber.deactivate()


def test_attach_policy_fails(mocker):
    env_vars = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "test_value", "type": "PLAINTEXT"}
    ]

    test_case = Case(env_vars)

    ssm_client = botocore.session.get_session().create_client(
        "ssm", config=get_config()
    )
    ssm_stubber = Stubber(ssm_client)

    ssm_stubber.add_response(
        "put_parameter",
        successful_parameter_response(),
        {
            "Name": test_case.parameter_name(env_vars[0]["name"]),
            "Description": ANY,
            "Value": env_vars[0]["value"],
            "Type": "SecureString",
            "Overwrite": False,
            "DataType": "text",
        },
    )

    ssm_stubber.activate()

    iam_client = botocore.session.get_session().create_client(
        "iam", config=get_config()
    )
    iam_stubber = Stubber(iam_client)

    iam_stubber.add_response("create_policy", test_case.policy())

    iam_stubber.add_client_error(
        "attach_role_policy",
        "ServiceFailure",
        http_status_code=500,
        expected_params=test_case.attach_params(),
    )

    iam_stubber.activate()

    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_ssm", return_value=ssm_client
    )
    mocker.patch(
        "ReplaceCodeBuildClearTextCredentials.connect_to_iam", return_value=iam_client
    )

    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.replace_credentials(test_case.event(), {})
    assert wrapped_exception.type == SystemExit

    ssm_stubber.deactivate()
    iam_stubber.deactivate()
