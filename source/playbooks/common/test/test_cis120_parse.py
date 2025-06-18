# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import botocore.session
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from parse_input import parse_event


def event():
    return {
        "expected_control_id": "2.3",
        "parse_id_pattern": "^arn:(?:aws|aws-cn|aws-us-gov):s3:::([A-Za-z0-9.-]{3,63})$",
        "Finding": {
            "ProductArn": "arn:aws:securityhub:us-east-2::product/aws/securityhub",
            "Types": [
                "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
            ],
            "Description": "Details: 2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "SchemaVersion": "2018-10-08",
            "Compliance": {
                "Status": "WARNING",
                "StatusReasons": [
                    {
                        "Description": "The finding is in a WARNING state, because the S3 Bucket associated with this rule is in a different region/account. This rule does not support cross-region/cross-account checks, so it is recommended to disable this control in this region/account and only run it in the region/account where the resource is located.",
                        "ReasonCode": "S3_BUCKET_CROSS_ACCOUNT_CROSS_REGION",
                    }
                ],
            },
            "GeneratorId": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/2.3",
            "FirstObservedAt": "2020-05-20T05:02:44.203Z",
            "CreatedAt": "2020-05-20T05:02:44.203Z",
            "RecordState": "ACTIVE",
            "Title": "2.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "Workflow": {"Status": "NEW"},
            "LastObservedAt": "2020-06-17T13:01:35.884Z",
            "Severity": {
                "Normalized": 90,
                "Label": "CRITICAL",
                "Product": 90,
                "Original": "CRITICAL",
            },
            "UpdatedAt": "2020-06-17T13:01:25.561Z",
            "WorkflowState": "NEW",
            "ProductFields": {
                "StandardsGuideArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                "StandardsGuideSubscriptionArn": "arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                "RuleId": "2.3",
                "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/standards-cis-2.3/remediation",
                "RelatedAWSResources:0/name": "securityhub-s3-bucket-public-read-prohibited-4414615a",
                "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                "RelatedAWSResources:1/name": "securityhub-s3-bucket-public-write-prohibited-f104fcda",
                "RelatedAWSResources:1/type": "AWS::Config::ConfigRule",
                "StandardsControlArn": "arn:aws:securityhub:us-east-2:111111111111:control/cis-aws-foundations-benchmark/v/1.2.0/2.3",
                "aws/securityhub/SeverityLabel": "CRITICAL",
                "aws/securityhub/ProductName": "Security Hub",
                "aws/securityhub/CompanyName": "AWS",
                "aws/securityhub/annotation": "The finding is in a WARNING state, because the S3 Bucket associated with this rule is in a different region/account. This rule does not support cross-region/cross-account checks, so it is recommended to disable this control in this region/account and only run it in the region/account where the resource is located.",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-2::product/aws/securityhub/arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/2.3/finding/f51c716c-b33c-4949-b748-2ffd22bdceec",
            },
            "AwsAccountId": "111111111111",
            "Id": "arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/2.3/finding/f51c716c-b33c-4949-b748-2ffd22bdceec",
            "Remediation": {
                "Recommendation": {
                    "Text": "For directions on how to fix this issue, please consult the AWS Security Hub CIS documentation.",
                    "Url": "https://docs.aws.amazon.com/console/securityhub/standards-cis-2.3/remediation",
                }
            },
            "Resources": [
                {
                    "Partition": "aws",
                    "Type": "AwsS3Bucket",
                    "Region": "us-east-2",
                    "Id": "arn:aws:s3:::cloudtrail-awslogs-111111111111-kjfskljdfl",
                }
            ],
        },
    }


def expected():
    return {
        "account_id": "111111111111",
        "resource_id": "cloudtrail-awslogs-111111111111-kjfskljdfl",
        "finding_id": "arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/2.3/finding/f51c716c-b33c-4949-b748-2ffd22bdceec",
        "product_arn": "arn:aws:securityhub:us-east-2::product/aws/securityhub",
        "control_id": "2.3",
        "object": {
            "Type": "AwsS3Bucket",
            "Id": "cloudtrail-awslogs-111111111111-kjfskljdfl",
            "OutputKey": "Remediation.Output",
        },
        "matches": ["cloudtrail-awslogs-111111111111-kjfskljdfl"],
        "details": {},
        "testmode": False,
        "resource": event().get("Finding").get("Resources")[0],
        "resource_region": "us-east-2",
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


def cis41_event():
    return {
        "expected_control_id": "4.1",
        "parse_id_pattern": "^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-[0-9]):[0-9]{12}:security-group/(sg-[a-f0-9]{8,17})$",
        "Finding": {
            "SchemaVersion": "2018-10-08",
            "Id": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/4.1/finding/f371b170-1881-4af0-9a33-840c81d91a04",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
            "ProductName": "Security Hub",
            "CompanyName": "AWS",
            "Region": "us-east-1",
            "GeneratorId": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/4.1",
            "AwsAccountId": "111111111111",
            "Types": [
                "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
            ],
            "FirstObservedAt": "2020-05-08T08:56:08.195Z",
            "LastObservedAt": "2021-07-20T16:43:29.362Z",
            "CreatedAt": "2020-05-08T08:56:08.195Z",
            "UpdatedAt": "2021-07-20T16:43:26.312Z",
            "Severity": {
                "Product": 70,
                "Label": "HIGH",
                "Normalized": 70,
                "Original": "HIGH",
            },
            "Title": "4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
            "Description": "Security groups provide stateful filtering of ingress/egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to port 22.",
            "Remediation": {
                "Recommendation": {
                    "Text": "For directions on how to fix this issue, please consult the AWS Security Hub CIS documentation.",
                    "Url": "https://docs.aws.amazon.com/console/securityhub/standards-cis-4.1/remediation",
                }
            },
            "ProductFields": {
                "StandardsGuideArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                "StandardsGuideSubscriptionArn": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                "RuleId": "4.1",
                "RecommendationUrl": "https://docs.aws.amazon.com/console/securityhub/standards-cis-4.1/remediation",
                "RelatedAWSResources:0/name": "securityhub-restricted-ssh-33f8347e",
                "RelatedAWSResources:0/type": "AWS::Config::ConfigRule",
                "StandardsControlArn": "arn:aws:securityhub:us-east-1:111111111111:control/cis-aws-foundations-benchmark/v/1.2.0/4.1",
                "aws/securityhub/ProductName": "Security Hub",
                "aws/securityhub/CompanyName": "AWS",
                "Resources:0/Id": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-087af114e4ae4c6ea",
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/securityhub/arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/4.1/finding/f371b170-1881-4af0-9a33-840c81d91a04",
            },
            "Resources": [
                {
                    "Type": "AwsEc2SecurityGroup",
                    "Id": "arn:aws:ec2:us-east-1:111111111111:security-group/sg-087af114e4ae4c6ea",
                    "Partition": "aws",
                    "Region": "us-east-1",
                    "Details": {
                        "AwsEc2SecurityGroup": {
                            "GroupName": "launch-wizard-17",
                            "GroupId": "sg-087af114e4ae4c6ea",
                            "OwnerId": "111111111111",
                            "VpcId": "vpc-e5b8f483",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                }
                            ],
                            "IpPermissionsEgress": [
                                {
                                    "IpProtocol": "-1",
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                }
                            ],
                        }
                    },
                }
            ],
            "Compliance": {"Status": "FAILED"},
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NOTIFIED"},
            "RecordState": "ACTIVE",
            "Note": {
                "Text": "Remediation failed for CIS control 4.1 in account 111111111111: No output available yet because the step is not successfully executed",
                "UpdatedBy": "update_text",
                "UpdatedAt": "2021-07-20T18:53:07.918Z",
            },
            "FindingProviderFields": {
                "Severity": {"Label": "HIGH", "Original": "HIGH"},
                "Types": [
                    "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
                ],
            },
        },
    }


def cis41_expected():
    return {
        "account_id": "111111111111",
        "resource_id": "sg-087af114e4ae4c6ea",
        "testmode": False,
        "finding_id": "arn:aws:securityhub:us-east-1:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/4.1/finding/f371b170-1881-4af0-9a33-840c81d91a04",
        "product_arn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        "control_id": "4.1",
        "object": {
            "Type": "AwsEc2SecurityGroup",
            "Id": "sg-087af114e4ae4c6ea",
            "OutputKey": "Remediation.Output",
        },
        "matches": ["sg-087af114e4ae4c6ea"],
        "details": cis41_event().get("Finding").get("Resources")[0].get("Details"),
        "resource": cis41_event().get("Finding").get("Resources")[0],
        "resource_region": "us-east-1",
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


def test_parse_cis41(mocker):
    expected_result = cis41_expected()
    expected_result["finding"] = cis41_event().get("Finding")
    parsed_event = parse_event(cis41_event(), {})
    assert parsed_event == expected_result


def test_parse_event_multimatch(mocker):
    expected_result = expected()
    expected_result["finding"] = event().get("Finding")
    expected_result["matches"] = ["aws", "cloudtrail-awslogs-111111111111-kjfskljdfl"]
    test_event = event()
    test_event["resource_index"] = 2
    test_event["parse_id_pattern"] = (
        "^arn:((?:aws|aws-cn|aws-us-gov)):s3:::([A-Za-z0-9.-]{3,63})$"
    )
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
    ] = "arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0//finding/f51c716c-b33c-4949-b748-2ffd22bdceec"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "ERROR: Finding Id is invalid: arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0//finding/f51c716c-b33c-4949-b748-2ffd22bdceec - missing Control Id"
    )


def test_control_id_nomatch(mocker):
    test_event = event()
    test_event["Finding"][
        "Id"
    ] = "arn:aws:securityhub:us-east-2:111111111111:subscription/cis-aws-foundations-benchmark/v/1.2.0/2.4/finding/f51c716c-b33c-4949-b748-2ffd22bdceec"
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_event(test_event, {})
    assert pytest_wrapped_e.type == SystemExit
    assert (
        pytest_wrapped_e.value.code
        == "ERROR: Control Id from input (2.4) does not match 2.3"
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
        == "ERROR: Invalid resource Id arn:aws:s3:::cloudtrail-awslogs-111111111111-kjfskljdfl"
    )


def test_no_resource_pattern(mocker):
    test_event = event()
    expected_result = expected()
    expected_result["finding"] = event().get("Finding")
    test_event["parse_id_pattern"] = ""
    expected_result["resource_id"] = (
        "arn:aws:s3:::cloudtrail-awslogs-111111111111-kjfskljdfl"
    )
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
