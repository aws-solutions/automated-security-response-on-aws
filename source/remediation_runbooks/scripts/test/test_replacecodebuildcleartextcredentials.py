# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import traceback
from collections.abc import Iterator
from json import dumps
from typing import Any

import boto3
import pytest
import ReplaceCodeBuildClearTextCredentials as remediation
from moto import mock_aws
from moto.codebuild.exceptions import InvalidInputException, ResourceNotFoundException
from moto.codebuild.responses import CodeBuildResponse
from moto.iam.exceptions import LimitExceededException
from moto.iam.responses import IamResponse
from moto.resourcegroupstaggingapi.models import ResourceGroupsTaggingAPIBackend
from moto.ssm.exceptions import InvalidResourceId
from moto.ssm.models import ssm_backends

REGION_NAME = "us-east-1"
ACCOUNT_ID = "123456789012"
PROJECT_NAME = "invoke-codebuild-2"
SERVICE_ROLE_NAME = f"codebuild-{PROJECT_NAME}-service-role"
POLICY_NAME = f"CodeBuildSSMParameterPolicy-{PROJECT_NAME}-{REGION_NAME}"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/{POLICY_NAME}"
EVENT: dict[str, object] = {"ProjectName": PROJECT_NAME}

ACCESS_KEY_VALUE = "fake-access-key-id-for-tests"
SECRET_KEY_VALUE = "fake-secret-access-key-for-tests"
RETAINED_VALUE = "a_non_credential_value"

EnvironmentVariable = dict[str, str]


def parameter_name(variable_name: str) -> str:
    return f"/CodeBuild/{PROJECT_NAME}/env/{variable_name}"


def parameter_arn(variable_name: str) -> str:
    return (
        f"arn:aws:ssm:{REGION_NAME}:{ACCOUNT_ID}:parameter"
        f"{parameter_name(variable_name)}"
    )


def update_project_in_moto(self: CodeBuildResponse) -> str:
    """moto does not implement CodeBuild UpdateProject."""
    name = self._get_param("name")
    project = self.codebuild_backend.codebuild_projects.get(name)
    if project is None:
        raise ResourceNotFoundException(f"Project cannot be found: {name}")
    project.project_metadata["environment"] = self._get_param("environment")
    return json.dumps({"project": project.project_metadata})


def tag_parameters_in_moto(
    self: ResourceGroupsTaggingAPIBackend,
    resource_arns: list[str],
    tags: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """moto's tagging API reports every SSM parameter as an unsupported service."""
    ssm_backend = ssm_backends[self.account_id][self.region_name]
    failed_resources = {}
    for arn in resource_arns:
        try:
            ssm_backend.add_tags_to_resource(
                "Parameter", arn.split(":parameter", 1)[1], tags
            )
        except InvalidResourceId:
            failed_resources[arn] = {
                "StatusCode": 400,
                "ErrorCode": "InvalidParameterException",
                "ErrorMessage": f"{arn} does not exist",
            }
    return failed_resources


def fail_operation(
    monkeypatch: pytest.MonkeyPatch,
    response_class: type,
    operation: str,
    error: Exception,
) -> None:
    """Make moto answer an operation with an error it would never raise itself."""

    def raise_error(self: Any) -> str:
        raise error

    monkeypatch.setattr(response_class, operation, raise_error, raising=False)


@pytest.fixture
def aws_services(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(
        CodeBuildResponse, "update_project", update_project_in_moto, raising=False
    )
    monkeypatch.setattr(
        ResourceGroupsTaggingAPIBackend, "tag_resources", tag_parameters_in_moto
    )
    with mock_aws():
        yield


def create_project(environment_variables: list[EnvironmentVariable]) -> None:
    role_arn = boto3.client("iam", region_name=REGION_NAME).create_role(
        RoleName=SERVICE_ROLE_NAME,
        Path="/service-role/",
        AssumeRolePolicyDocument=dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codebuild.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )["Role"]["Arn"]
    boto3.client("codebuild", region_name=REGION_NAME).create_project(
        name=PROJECT_NAME,
        source={"type": "GITHUB", "location": "https://github.com/example/repo.git"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/standard:7.0",
            "computeType": "BUILD_GENERAL1_SMALL",
            "environmentVariables": environment_variables,
        },
        serviceRole=role_arn,
    )


def read_environment_variables() -> list[EnvironmentVariable]:
    project = boto3.client("codebuild", region_name=REGION_NAME).batch_get_projects(
        names=[PROJECT_NAME]
    )["projects"][0]
    environment_variables: list[EnvironmentVariable] = project["environment"][
        "environmentVariables"
    ]
    return environment_variables


def read_secure_parameter(variable_name: str) -> dict[str, Any]:
    parameter: dict[str, Any] = boto3.client(
        "ssm", region_name=REGION_NAME
    ).get_parameter(Name=parameter_name(variable_name), WithDecryption=True)[
        "Parameter"
    ]
    return parameter


def stored_in_parameter_store(variable_name: str) -> EnvironmentVariable:
    return {
        "name": variable_name,
        "type": "PARAMETER_STORE",
        "value": parameter_name(variable_name),
    }


def run_remediation_expecting_exit() -> str:
    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.replace_credentials(EVENT, {})
    return str(wrapped_exception.value)


@pytest.fixture
def project_with_credentials(aws_services: None) -> list[EnvironmentVariable]:
    environment_variables = [
        {"name": "AWS_ACCESS_KEY_ID", "value": ACCESS_KEY_VALUE, "type": "PLAINTEXT"},
        {
            "name": "AWS_SECRET_ACCESS_KEY",
            "value": SECRET_KEY_VALUE,
            "type": "PLAINTEXT",
        },
        {
            "name": "AN_ACCEPTABLE_PARAMETER",
            "value": RETAINED_VALUE,
            "type": "PLAINTEXT",
        },
    ]
    create_project(environment_variables)
    return environment_variables


def test_replaces_plaintext_credentials_with_secure_parameters(
    project_with_credentials: list[EnvironmentVariable],
) -> None:
    # ARRANGE (project_with_credentials)

    # ACT
    result = remediation.replace_credentials(EVENT, {})

    # ASSERT
    assert read_environment_variables() == [
        stored_in_parameter_store("AWS_ACCESS_KEY_ID"),
        stored_in_parameter_store("AWS_SECRET_ACCESS_KEY"),
        project_with_credentials[2],
    ]
    for variable_name, original_value in (
        ("AWS_ACCESS_KEY_ID", ACCESS_KEY_VALUE),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY_VALUE),
    ):
        stored = read_secure_parameter(variable_name)
        assert stored["Type"] == "SecureString"
        assert stored["Value"] == original_value
        tags = boto3.client("ssm", region_name=REGION_NAME).list_tags_for_resource(
            ResourceType="Parameter", ResourceId=parameter_name(variable_name)
        )["TagList"]
        assert tags == [
            {"Key": "Solutions:SolutionName", "Value": remediation.SOLUTION_TAG_VALUE}
        ]

    iam = boto3.client("iam", region_name=REGION_NAME)
    attached = iam.list_attached_role_policies(RoleName=SERVICE_ROLE_NAME)
    assert [policy["PolicyName"] for policy in attached["AttachedPolicies"]] == [
        POLICY_NAME
    ]
    policy_version = iam.get_policy_version(PolicyArn=POLICY_ARN, VersionId="v1")
    assert policy_version["PolicyVersion"]["Document"]["Statement"] == [
        {
            "Effect": "Allow",
            "Action": ["ssm:GetParameter", "ssm:GetParameters"],
            "Resource": f"arn:aws:ssm:{REGION_NAME}:{ACCOUNT_ID}:parameter"
            f"/CodeBuild/{PROJECT_NAME}/*",
        }
    ]

    assert result["ParameterNames"] == [
        parameter_name("AWS_ACCESS_KEY_ID"),
        parameter_name("AWS_SECRET_ACCESS_KEY"),
    ]
    assert result["ParameterArns"] == [
        parameter_arn("AWS_ACCESS_KEY_ID"),
        parameter_arn("AWS_SECRET_ACCESS_KEY"),
    ]
    assert result["ResourceArn"] == POLICY_ARN
    assert result["Policy"]["Policy"]["Arn"] == POLICY_ARN
    assert isinstance(result["Policy"]["Policy"]["CreateDate"], str)
    assert result["TaggingResult"] == {"success": True, "tagged_count": 2}


def test_published_output_omits_environment_values(
    project_with_credentials: list[EnvironmentVariable],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The returned payload and stdout are both published, so neither holds a value."""
    # ARRANGE (project_with_credentials)

    # ACT
    result = remediation.replace_credentials(EVENT, {})

    # ASSERT
    published_output = dumps(result, default=str) + capsys.readouterr().out
    assert result["ParameterNames"]
    for environment_value in (ACCESS_KEY_VALUE, SECRET_KEY_VALUE, RETAINED_VALUE):
        assert environment_value not in published_output


def test_leaves_credentials_already_in_parameter_store_untouched(
    aws_services: None,
) -> None:
    # ARRANGE
    already_stored = {
        "name": "AWS_ACCESS_KEY_ID",
        "value": "an_existing_parameter",
        "type": "PARAMETER_STORE",
    }
    create_project(
        [
            already_stored,
            {
                "name": "AWS_SECRET_ACCESS_KEY",
                "value": SECRET_KEY_VALUE,
                "type": "PLAINTEXT",
            },
        ]
    )

    # ACT
    result = remediation.replace_credentials(EVENT, {})

    # ASSERT
    assert read_environment_variables() == [
        already_stored,
        stored_in_parameter_store("AWS_SECRET_ACCESS_KEY"),
    ]
    assert result["ParameterNames"] == [parameter_name("AWS_SECRET_ACCESS_KEY")]
    created = boto3.client("ssm", region_name=REGION_NAME).describe_parameters()
    assert [parameter["Name"] for parameter in created["Parameters"]] == [
        parameter_name("AWS_SECRET_ACCESS_KEY")
    ]


def test_continues_when_parameters_and_policy_already_exist(
    project_with_credentials: list[EnvironmentVariable],
) -> None:
    # ARRANGE: a previous run created these before it failed
    ssm = boto3.client("ssm", region_name=REGION_NAME)
    for variable_name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        ssm.put_parameter(
            Name=parameter_name(variable_name),
            Value="value_from_a_previous_run",
            Type="SecureString",
        )
    boto3.client("iam", region_name=REGION_NAME).create_policy(
        PolicyName=POLICY_NAME,
        PolicyDocument=dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "ssm:GetParameter", "Resource": "*"}
                ],
            }
        ),
    )

    # ACT
    result = remediation.replace_credentials(EVENT, {})

    # ASSERT
    assert read_environment_variables() == [
        stored_in_parameter_store("AWS_ACCESS_KEY_ID"),
        stored_in_parameter_store("AWS_SECRET_ACCESS_KEY"),
        project_with_credentials[2],
    ]
    assert result["ResourceArn"] == POLICY_ARN
    attached = boto3.client("iam", region_name=REGION_NAME).list_attached_role_policies(
        RoleName=SERVICE_ROLE_NAME
    )
    assert [policy["PolicyName"] for policy in attached["AttachedPolicies"]] == [
        POLICY_NAME
    ]


def test_second_run_finds_nothing_to_replace(
    project_with_credentials: list[EnvironmentVariable],
) -> None:
    # ARRANGE
    remediation.replace_credentials(EVENT, {})
    environment_after_first_run = read_environment_variables()

    # ACT
    result = remediation.replace_credentials(EVENT, {})

    # ASSERT
    assert read_environment_variables() == environment_after_first_run
    assert result["ParameterNames"] == []
    assert result["ResourceArn"] == POLICY_ARN
    assert result["TaggingResult"] == {"success": True, "tagged_count": 0}


def test_project_not_found_exits(aws_services: None) -> None:
    # ARRANGE (no project exists)

    # ACT
    exit_message = run_remediation_expecting_exit()

    # ASSERT
    assert "was not found" in exit_message


def test_project_read_failure_is_reported(
    aws_services: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ARRANGE
    fail_operation(
        monkeypatch,
        CodeBuildResponse,
        "batch_get_projects",
        InvalidInputException("The request was rejected."),
    )

    # ACT
    exit_message = run_remediation_expecting_exit()

    # ASSERT
    assert "InvalidInputException" in exit_message


def test_project_read_failure_message_omits_response_content(
    aws_services: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """botocore quotes response content it cannot parse, and the response holds secrets."""
    # ARRANGE: a field botocore must parse as a timestamp carries a credential
    unparsable_response = dumps(
        {"projects": [{"name": PROJECT_NAME, "created": ACCESS_KEY_VALUE}]}
    )
    monkeypatch.setattr(
        CodeBuildResponse,
        "batch_get_projects",
        lambda self: unparsable_response,
        raising=False,
    )

    # ACT
    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.get_project(PROJECT_NAME)

    # ASSERT
    failure_message = str(wrapped_exception.value)
    formatted_traceback = "".join(traceback.format_exception(wrapped_exception.value))
    assert PROJECT_NAME in failure_message
    assert ACCESS_KEY_VALUE not in failure_message
    assert ACCESS_KEY_VALUE not in formatted_traceback


def test_tag_parameters_reports_the_parameters_it_could_not_tag(
    aws_services: None,
) -> None:
    # ARRANGE
    boto3.client("ssm", region_name=REGION_NAME).put_parameter(
        Name=parameter_name("AWS_ACCESS_KEY_ID"), Value="value", Type="SecureString"
    )
    missing_arn = parameter_arn("AWS_SECRET_ACCESS_KEY")

    # ACT
    result = remediation.tag_parameters(
        [parameter_arn("AWS_ACCESS_KEY_ID"), missing_arn]
    )

    # ASSERT
    assert result["success"] is False
    assert result["tagged_count"] == 1
    assert list(result["failed_resources"]) == [missing_arn]


def test_put_parameter_failure_leaves_project_unchanged(aws_services: None) -> None:
    # ARRANGE: SSM rejects an empty parameter value
    environment_variables = [
        {"name": "AWS_ACCESS_KEY_ID", "value": "", "type": "PLAINTEXT"}
    ]
    create_project(environment_variables)

    # ACT
    exit_message = run_remediation_expecting_exit()

    # ASSERT
    assert "PutParameter" in exit_message
    assert read_environment_variables() == environment_variables


def test_create_policy_failure_leaves_project_unchanged(
    project_with_credentials: list[EnvironmentVariable], monkeypatch: pytest.MonkeyPatch
) -> None:
    # ARRANGE
    fail_operation(
        monkeypatch,
        IamResponse,
        "create_policy",
        LimitExceededException("Cannot exceed quota for PoliciesPerAccount"),
    )

    # ACT
    exit_message = run_remediation_expecting_exit()

    # ASSERT
    assert "CreatePolicy" in exit_message
    assert read_environment_variables() == project_with_credentials


def test_attach_policy_failure_leaves_project_unchanged(
    project_with_credentials: list[EnvironmentVariable],
) -> None:
    # ARRANGE: the project's service role no longer exists
    boto3.client("iam", region_name=REGION_NAME).delete_role(RoleName=SERVICE_ROLE_NAME)

    # ACT
    exit_message = run_remediation_expecting_exit()

    # ASSERT
    assert "AttachRolePolicy" in exit_message
    assert read_environment_variables() == project_with_credentials


def test_update_failure_message_omits_quoted_environment_value(
    project_with_credentials: list[EnvironmentVariable], monkeypatch: pytest.MonkeyPatch
) -> None:
    # ARRANGE: the service quotes back a value from the request
    fail_operation(
        monkeypatch,
        CodeBuildResponse,
        "update_project",
        InvalidInputException(f"Invalid environment variable value: {RETAINED_VALUE}"),
    )

    # ACT
    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.replace_credentials(EVENT, {})

    # ASSERT
    failure_message = str(wrapped_exception.value)
    formatted_traceback = "".join(traceback.format_exception(wrapped_exception.value))
    assert "InvalidInputException" in failure_message
    assert RETAINED_VALUE not in failure_message
    assert RETAINED_VALUE not in formatted_traceback


def test_update_failure_message_omits_invalid_environment_value(
    aws_services: None,
) -> None:
    """A botocore validation error is not a ClientError and quotes the failing value."""
    # ARRANGE
    invalid_value = 48151623
    environment = {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/standard:7.0",
        "computeType": "BUILD_GENERAL1_SMALL",
        "environmentVariables": [
            {
                "name": "AN_ACCEPTABLE_PARAMETER",
                "value": invalid_value,
                "type": "PLAINTEXT",
            }
        ],
    }

    # ACT
    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.update_project_environment(PROJECT_NAME, environment)

    # ASSERT
    failure_message = str(wrapped_exception.value)
    formatted_traceback = "".join(traceback.format_exception(wrapped_exception.value))
    assert "ParamValidationError" in failure_message
    assert str(invalid_value) not in failure_message
    assert str(invalid_value) not in formatted_traceback


@pytest.mark.parametrize("project_name", [None, ""])
def test_missing_project_name_is_rejected(project_name: str | None) -> None:
    # ARRANGE
    event: dict[str, object] = (
        {} if project_name is None else {"ProjectName": project_name}
    )

    # ACT
    with pytest.raises(SystemExit) as wrapped_exception:
        remediation.replace_credentials(event, {})

    # ASSERT
    assert "ProjectName is required" in str(wrapped_exception.value)


def test_parse_project_arn_valid():
    """Test parse_project_arn with valid ARN"""
    arn = f"arn:aws:codebuild:{REGION_NAME}:111111111111:project/test-project"
    partition, region, account = remediation.parse_project_arn(arn)

    assert partition == "aws"
    assert region == REGION_NAME
    assert account == "111111111111"


def test_parse_project_arn_gov_cloud():
    """Test parse_project_arn with GovCloud ARN"""
    arn = "arn:aws-us-gov:codebuild:us-gov-west-1:111111111111:project/test-project"
    partition, region, account = remediation.parse_project_arn(arn)

    assert partition == "aws-us-gov"
    assert region == "us-gov-west-1"
    assert account == "111111111111"


def test_parse_project_arn_none():
    """Test parse_project_arn with None raises ValueError"""
    with pytest.raises(ValueError) as exc_info:
        remediation.parse_project_arn(None)

    assert "CodeBuild Project ARN could not be found" in str(exc_info.value)


def test_parse_project_arn_empty():
    """Test parse_project_arn with empty string raises ValueError"""
    with pytest.raises(ValueError) as exc_info:
        remediation.parse_project_arn("")

    assert "CodeBuild Project ARN could not be found" in str(exc_info.value)


def test_parse_project_arn_invalid_format():
    """Test parse_project_arn with invalid ARN format raises ValueError"""
    invalid_arn = "arn:aws:s3:::my-bucket"

    with pytest.raises(ValueError) as exc_info:
        remediation.parse_project_arn(invalid_arn)

    assert "Invalid CodeBuild project ARN format" in str(exc_info.value)
