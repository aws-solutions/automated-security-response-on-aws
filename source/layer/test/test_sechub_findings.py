# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Simple test to validate that the request format coming from the Cfn template
will turn into a valid API call.
"""
import json

import boto3
import layer.sechub_findings as findings
import pytest
from botocore.stub import Stubber
from layer.logger import Logger

log_level = "info"
logger = Logger(loglevel=log_level)
test_data = "test/test_json_data/"

my_session = boto3.session.Session()
my_region = my_session.region_name


# ------------------------------------------------------------------------------
# CIS v1.2.0
# ------------------------------------------------------------------------------
def test_parse_cis_v120(mocker):
    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/version",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert (
        finding.generator_id
        == "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3"
    )
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "cis-aws-foundations-benchmark"
    assert finding.standard_shortname == "CIS"
    assert finding.standard_version == "1.2.0"
    assert finding.standard_control == "1.3"
    assert finding.standard_version_supported == "True"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def test_parse_bad_imported():
    test_file = open(test_data + "CIS-bad.json")
    event = json.loads(test_file.read())
    test_file.close()

    with pytest.raises(findings.InvalidFindingJson):
        findings.Finding(event["detail"]["findings"][0])


# ------------------------------------------------------------------------------
# CIS v1.7.0 finding should show unsupported
# ------------------------------------------------------------------------------
def test_parse_unsupported_version(mocker):
    test_data_in = open(test_data + "CIS_unsupversion.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.7.0/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/1.7.0/shortname",
                "DataType": "text",
            }
        },
    )

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])

    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert (
        finding.generator_id
        == "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.7.0/rule/1.6"
    )
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "cis-aws-foundations-benchmark"
    assert finding.standard_shortname == "CIS"
    assert finding.standard_version == "1.7.0"
    assert finding.standard_control == "1.6"
    assert finding.standard_version_supported == "False"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
# AFSBP v1.0.0
# ------------------------------------------------------------------------------
def test_parse_afsbp_v100(mocker):
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f"arn:aws:ssm:us-{my_region}-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/version",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "aws-foundational-security-best-practices"
    assert finding.standard_shortname == "AFSBP"
    assert finding.standard_version == "1.0.0"
    assert finding.standard_control == "EC2.7"
    assert finding.standard_version_supported == "True"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
# Security Standard not found
# ------------------------------------------------------------------------------
def test_undefined_security_standard(mocker):
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    event["detail"]["findings"][0]["ProductFields"][
        "StandardsControlArn"
    ] = "arn:aws:securityhub:::standards/aws-invalid-security-standard/v/1.2.3/ABC.1"

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )

    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )

    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "aws-invalid-security-standard"
    assert finding.standard_shortname == "error"
    assert finding.security_standard == "notfound"
    assert finding.standard_version == "1.2.3"
    assert finding.standard_control == "ABC.1"
    assert finding.standard_version_supported == "False"

    stubbed_ssm_client.deactivate()


def test_security_control(mocker):
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    event["detail"]["findings"][0]["ProductFields"]["StandardsControlArn"] = None
    event["detail"]["findings"][0]["Compliance"]["SecurityControlId"] = "EC2.7"

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/security-controls/2.0.0/shortname",
                "Type": "String",
                "Value": "SC",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f"arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/security-controls/2.0.0/shortname",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/security-controls/2.0.0/status",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f"arn:aws:ssm:us-{my_region}-1:111111111111:parameter/Solutions/SO0111/security-controls/2.0.0/status",
                "DataType": "text",
            }
        },
    )
    stubbed_ssm_client.activate()

    finding = findings.Finding(event["detail"]["findings"][0])
    assert finding.details.get("Id") == event["detail"]["findings"][0]["Id"]
    assert finding.account_id == "111111111111"
    assert finding.standard_name == "security-control"
    assert finding.standard_version == "2.0.0"
    assert finding.standard_control == "EC2.7"
