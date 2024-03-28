# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from parse_input import parse_event


def event():
    return {
        "expected_control_id": "S3.12",
        "parse_id_pattern": "^arn:aws:s3:::(.*)$",
        "Finding": {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:111111111111:security-control/S3.12/finding/c5dcc868-c633-448d-92c7-bb19bbdcfe00",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "ProductName": "Security Hub",
            "CompanyName": "AWS",
            "Region": "us-east-1",
            "GeneratorId": "security-control/S3.12",
            "AwsAccountId": "111111111111",
            "Types": [
                "Software and Configuration Checks/Industry and Regulatory Standards"
            ],
            "FirstObservedAt": "2022-11-29T22:33:23.371Z",
            "LastObservedAt": "2023-02-24T16:33:22.030Z",
            "CreatedAt": "2022-11-29T22:33:23.371Z",
            "UpdatedAt": "2023-02-24T16:33:18.102Z",
            "Severity": {
                "Label": "INFORMATIONAL",
                "Normalized": 0,
                "Original": "INFORMATIONAL",
            },
            "Title": "S3 access control lists (ACLs) should not be used to manage user access to buckets",
            "Description": "This control checks if S3 buckets allow user permissions via access control lists (ACLs). This control fails if ACLs are configured for user access on S3 Bucket.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
                    "Url": "https://docs.aws.amazon.com/console/securityhub/S3.12/remediation",
                }
            },
            "ProductFields": {
                "RelatedAWSResources:0/name": "securityhub-s3-bucket-acl-prohibited-1b1e5339",
                "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                "aws/securityhub/ProductName": "Security Hub",
                "aws/securityhub/CompanyName": "AWS",
                "Resources:0/Id": "arn:aws:s3:::asr-scv-reference",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:111111111111:security-control/S3.12/finding/c5dcc868-c633-448d-92c7-bb19bbdcfe00",
            },
            "Resources": [
                {
                    "Type": "AwsS3Bucket",
                    "Id": "arn:aws:s3:::asr-scv-reference",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "Details": {
                        "AwsS3Bucket": {
                            "OwnerId": "93b93c44fd03f06ac297d9923da9bf86507301cfc9485b1d29c992241afd5182",
                            "CreatedAt": "2022-10-27T20:32:54.000Z",
                        }
                    },
                }
            ],
            "Compliance": {
                "Status": "PASSED",
                "SecurityControlId": "S3.12",
                "AssociatedStandards": [
                    {
                        "StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"
                    }
                ],
            },
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
            "FindingProviderFields": {
                "Severity": {"Label": "INFORMATIONAL", "Original": "INFORMATIONAL"},
                "Types": [
                    "Software and Configuration Checks/Industry and Regulatory Standards"
                ],
            },
            "ProcessedAt": "2023-02-24T16:33:23.639Z",
        },
    }


def expected():
    return {
        "account_id": "111111111111",
        "resource_id": "asr-scv-reference",
        "control_id": "S3.12",
        "testmode": False,
        "finding_id": "arn:aws:securityhub:us-east-1:111111111111:security-control/S3.12/finding/c5dcc868-c633-448d-92c7-bb19bbdcfe00",
        "product_arn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "object": {
            "Type": "AwsS3Bucket",
            "Id": "asr-scv-reference",
            "OutputKey": "Remediation.Output",
        },
        "matches": ["asr-scv-reference"],
        "details": {
            "AwsS3Bucket": {
                "CreatedAt": "2022-10-27T20:32:54.000Z",
                "OwnerId": "93b93c44fd03f06ac297d9923da9bf86507301cfc9485b1d29c992241afd5182",
            }
        },
        "resource": event().get("Finding").get("Resources")[0],
        "resource_region": None,
        "aws_config_rule": {
            "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
            "ConfigRuleArn": "arn:aws:config:us-east-1:111111111111:config-rule/config-rule-vye3dl",
            "ConfigRuleId": "config-rule-vye3dl",
            "Description": "Checks whether the S3 bucket policy denies the put-object requests that are not encrypted using AES-256 or AWS KMS.",
            "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
            "Source": {
                "Owner": "AWS",
                "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
            },
            "InputParameters": "{}",
            "ConfigRuleState": "ACTIVE",
        },
        "input_params": {},
    }


def config_rule():
    return {
        "ConfigRules": [
            {
                "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
                "ConfigRuleArn": "arn:aws:config:us-east-1:111111111111:config-rule/config-rule-vye3dl",
                "ConfigRuleId": "config-rule-vye3dl",
                "Description": "Checks whether the S3 bucket policy denies the put-object requests that are not encrypted using AES-256 or AWS KMS.",
                "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
                },
                "InputParameters": "{}",
                "ConfigRuleState": "ACTIVE",
            }
        ]
    }


def ssm_parm():
    return {
        "Parameter": {
            "Name": "Solutions/SO0111/member_version",
            "Type": "String",
            "Value": "v1.5.0",
        }
    }


BOTO_CONFIG = Config(retries={"mode": "standard"})


@pytest.fixture(autouse=True)
def run_before_and_after_tests(mocker):
    cfg_client = botocore.session.get_session().create_client(
        "config", config=BOTO_CONFIG
    )
    cfg_stubber = Stubber(cfg_client)
    cfg_stubber.add_response("describe_config_rules", config_rule())
    cfg_stubber.activate()
    mocker.patch("parse_input.connect_to_config", return_value=cfg_client)

    ssm_client = botocore.session.get_session().create_client("ssm", config=BOTO_CONFIG)
    ssm_stubber = Stubber(ssm_client)
    ssm_stubber.add_response("get_parameter", ssm_parm())
    ssm_stubber.activate()
    mocker.patch("parse_input.connect_to_ssm", return_value=ssm_client)
    yield

    cfg_stubber.deactivate()
    ssm_stubber.deactivate()


def test_parse_event(mocker):
    expected_result = expected()
    expected_result["finding"] = event().get("Finding")
    parsed_event = parse_event(event(), {})
    assert parsed_event == expected_result


def test_parse_event_multimatch(mocker):
    expected_result = expected()
    expected_result["finding"] = event().get("Finding")
    expected_result["matches"] = ["s3", "asr-scv-reference"]
    test_event = event()
    test_event["resource_index"] = 2
    test_event["parse_id_pattern"] = "^arn:aws:(.*):::(.*)$"
    parsed_event = parse_event(test_event, {})
    assert parsed_event == expected_result


def test_bad_finding_id(mocker):
    test_event = event()
    test_event["Finding"]["Id"] = "badvalue"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == "ERROR: Finding Id is invalid: badvalue"


def test_bad_control_id(mocker):
    test_event = event()
    test_event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-1:111111111111:subscription/pci-dss/v/3.2.1//finding/fec91aaf-5016-4c40-9d24-9966e4be80c4"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "ERROR: Finding Id is invalid: arn:aws:securityhub:us-east-1:111111111111:subscription/pci-dss/v/3.2.1//finding/fec91aaf-5016-4c40-9d24-9966e4be80c4 - missing Control Id"
    )


def test_control_id_nomatch(mocker):
    test_event = event()
    test_event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-2:111111111111:subscription/pci-dss/v/3.2.1/2.4/finding/fec91aaf-5016-4c40-9d24-9966e4be80c4"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "ERROR: Control Id from input (2.4) does not match S3.12"
    )


def test_bad_account_id(mocker):
    test_event = event()
    test_event["Finding"]["AwsAccountId"] = "1234123412345"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code == "ERROR: AwsAccountId is invalid: 1234123412345"
    )


def test_bad_productarn(mocker):
    test_event = event()
    test_event["Finding"]["ProductArn"] = "badvalue"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == "ERROR: ProductArn is invalid: badvalue"


def test_bad_resource_match(mocker):
    test_event = event()
    test_event["parse_id_pattern"] = (
        "^arn:(?:aws|aws-cn|aws-us-gov):logs:::([A-Za-z0-9.-]{3,63})$"
    )
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "ERROR: Invalid resource Id arn:aws:s3:::asr-scv-reference"
    )


def test_no_resource_pattern(mocker):
    test_event = event()
    expected_result = expected()
    expected_result["finding"] = event().get("Finding")
    test_event["parse_id_pattern"] = ""
    expected_result["resource_id"] = "arn:aws:s3:::asr-scv-reference"
    expected_result["matches"] = []
    expected_result["object"]["Id"] = expected_result["resource_id"]
    parsed_event = parse_event(test_event, {})
    assert parsed_event == expected_result


def test_no_resource_pattern_no_resource_id(mocker):
    test_event = event()

    test_event["parse_id_pattern"] = ""
    test_event["Finding"]["Resources"][0]["Id"] = ""

    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "ERROR: Resource Id is missing from the finding json Resources (Id)"
    )
