# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import re
from json import dumps

import boto3
from boto3 import client
from botocore.config import Config
from botocore.exceptions import ClientError

boto_config = Config(retries={"mode": "standard"})

CREDENTIAL_NAMES_UPPER = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
SOLUTION_TAG_KEY = "Solutions:SolutionName"
SOLUTION_TAG_VALUE = "automated-security-response-on-aws"


def connect_to_ssm(boto_config: Config):
    return client("ssm", config=boto_config)


def connect_to_iam(boto_config: Config):
    return client("iam", config=boto_config)


def is_clear_text_credential(env_var: dict) -> bool:
    if env_var.get("type") != "PLAINTEXT":
        return False
    return any(
        env_var.get("name").upper() == credential_name
        for credential_name in CREDENTIAL_NAMES_UPPER
    )


def get_project_ssm_namespace(project_name: str) -> str:
    return f"/CodeBuild/{project_name}"


def create_parameter(
    project_name: str, env_var: dict, region: str, account_id: str, partition: str
) -> tuple[dict | None, str, str]:
    env_var_name = env_var.get("name")
    parameter_name = f"{get_project_ssm_namespace(project_name)}/env/{env_var_name}"

    ssm_client = connect_to_ssm(boto_config)
    try:
        response = ssm_client.put_parameter(
            Name=parameter_name,
            Description="Automatically created by ASR",
            Value=env_var.get("value"),
            Type="SecureString",
            Overwrite=False,
            DataType="text",
        )
    except ClientError as client_exception:
        exception_type = client_exception.response["Error"]["Code"]
        if exception_type == "ParameterAlreadyExists":
            print(
                f"Parameter {parameter_name} already exists. This remediation may have been run before."
            )
            print("Ignoring exception - remediation continues.")
            response = None
        else:
            exit(f"ERROR: Unhandled client exception: {client_exception}")
    except Exception as e:
        exit(f"ERROR: could not create SSM parameter {parameter_name}: {str(e)}")

    parameter_arn = (
        f"arn:{partition}:ssm:{region}:{account_id}:parameter{parameter_name}"
    )
    return response, parameter_name, parameter_arn


def create_policy(region: str, account: str, partition: str, project_name: str) -> dict:
    iam_client = connect_to_iam(boto_config)
    policy_resource_filter = f"arn:{partition}:ssm:{region}:{account}:parameter{get_project_ssm_namespace(project_name)}/*"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ssm:GetParameter", "ssm:GetParameters"],
                "Resource": policy_resource_filter,
            }
        ],
    }
    policy_name = f"CodeBuildSSMParameterPolicy-{project_name}-{region}"
    try:
        response = iam_client.create_policy(
            Description="Automatically created by ASR",
            PolicyDocument=dumps(policy_document),
            PolicyName=policy_name,
        )
    except ClientError as client_exception:
        exception_type = client_exception.response["Error"]["Code"]
        if exception_type == "EntityAlreadyExists":
            print(
                f'Policy {""} already exists. This remediation may have been run before.'
            )
            print("Ignoring exception - remediation continues.")
            # Attach needs to know the ARN of the created policy
            response = {
                "Policy": {
                    "Arn": f"arn:{partition}:iam::{account}:policy/{policy_name}"
                }
            }
        else:
            exit(f"ERROR: Unhandled client exception: {client_exception}")
    except Exception as e:
        exit(f"ERROR: could not create access policy {policy_name}: {str(e)}")
    return response


def attach_policy(policy_arn: str, service_role_name: str) -> dict:
    iam_client = connect_to_iam(boto_config)
    try:
        response = iam_client.attach_role_policy(
            PolicyArn=policy_arn, RoleName=service_role_name
        )
    except ClientError as client_exception:
        exit(f"ERROR: Unhandled client exception: {client_exception}")
    except Exception as e:
        exit(
            f"ERROR: could not attach policy {policy_arn} to role {service_role_name}: {str(e)}"
        )
    return response


def parse_project_arn(arn: str | None) -> tuple[str, str, str]:
    """Parse CodeBuild project ARN to extract partition, region, and account.

    Args:
        arn: CodeBuild project ARN

    Returns:
        Tuple of (partition, region, account)

    Raises:
        ValueError: If ARN is None or doesn't match expected format
    """
    if not arn:
        raise ValueError("CodeBuild Project ARN could not be found.")

    pattern = re.compile(
        r"arn:(aws[a-zA-Z-]*):codebuild:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):project/[A-Za-z0-9][A-Za-z0-9\-_]{1,254}$"
    )
    match = pattern.match(arn)
    if match:
        partition = match.group(1)
        region = match.group(2)
        account = match.group(3)
        return partition, region, account
    else:
        raise ValueError(f"Invalid CodeBuild project ARN format: {arn}")


def tag_parameters(parameter_arns: list[str]) -> dict:
    """Tag SSM parameters with solution tag using Resource Groups Tagging API.

    Args:
        parameter_arns: List of SSM parameter ARNs to tag

    Returns:
        Dictionary with success status, tagged count, and optional error info
    """
    if not parameter_arns:
        return {"success": True, "tagged_count": 0}

    tagging_client = boto3.client("resourcegroupstaggingapi", config=boto_config)

    try:
        response = tagging_client.tag_resources(
            ResourceARNList=parameter_arns, Tags={SOLUTION_TAG_KEY: SOLUTION_TAG_VALUE}
        )

        failed_resources = response.get("FailedResourcesMap", {})

        if failed_resources:
            print(f"Failed to tag some parameters: {failed_resources}")
            return {
                "success": False,
                "tagged_count": len(parameter_arns) - len(failed_resources),
                "failed_resources": failed_resources,
            }

        print(f"Successfully tagged {len(parameter_arns)} parameters")
        return {"success": True, "tagged_count": len(parameter_arns)}

    except ClientError as e:
        error_message = str(e)
        print(f"Error tagging parameters: {error_message}")
        return {"success": False, "tagged_count": 0, "error": error_message}


def replace_credentials(event: dict, _: dict) -> dict:
    """Replace clear text credentials in CodeBuild project with SSM parameters.

    Args:
        event: Lambda event containing ProjectInfo
        _: Lambda context (unused)

    Returns:
        Dictionary with updated project environment and tagging results
    """
    project_info = event.get("ProjectInfo")
    project_name = project_info.get("name")
    project_env = project_info.get("environment")
    project_env_vars = project_env.get("environmentVariables")
    updated_project_env_vars = []
    parameters = []
    parameter_arns = []

    partition, region, account = parse_project_arn(project_info.get("arn"))

    for env_var in project_env_vars:
        if is_clear_text_credential(env_var):
            parameter_response, parameter_name, parameter_arn = create_parameter(
                project_name, env_var, region, account, partition
            )
            updated_env_var = {
                "name": env_var.get("name"),
                "type": "PARAMETER_STORE",
                "value": parameter_name,
            }
            updated_project_env_vars.append(updated_env_var)
            parameters.append(parameter_response)
            parameter_arns.append(parameter_arn)
        else:
            updated_project_env_vars.append(env_var)

    updated_project_env = project_env
    updated_project_env["environmentVariables"] = updated_project_env_vars

    policy = create_policy(region, account, partition, project_name)
    service_role_arn = project_info.get("serviceRole")
    service_role_name = service_role_arn[service_role_arn.rfind("/") + 1 :]
    attach_response = attach_policy(policy["Policy"]["Arn"], service_role_name)

    # datetimes are not serializable, so convert them to ISO 8601 strings
    policy_datetime_keys = ["CreateDate", "UpdateDate"]
    for key in policy_datetime_keys:
        if key in policy["Policy"]:
            policy["Policy"][key] = policy["Policy"][key].isoformat()

    policy_arn = policy["Policy"]["Arn"]

    # Tag the SSM parameters
    tagging_result = tag_parameters(parameter_arns)

    return {
        "UpdatedProjectEnv": updated_project_env,
        "Parameters": parameters,
        "Policy": policy,
        "AttachResponse": attach_response,
        "ResourceArn": policy_arn,
        "ParameterArns": parameter_arns,
        "TaggingResult": tagging_result,
    }
