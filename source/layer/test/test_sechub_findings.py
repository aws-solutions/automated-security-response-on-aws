# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
from typing import Any

import boto3
import layer.sechub_findings as findings
import pytest
from botocore.stub import Stubber

log_level = "info"
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
    assert finding.playbook_enabled == "True"

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
    assert finding.playbook_enabled == "False"

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
    assert finding.playbook_enabled == "True"

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
    assert finding.playbook_enabled == "False"

    stubbed_ssm_client.deactivate()


# ------------------------------------------------------------------------------
# Test update_text_and_status method
# ------------------------------------------------------------------------------
def test_update_text_and_status_asff_format(mocker):
    """Test update_text_and_status with ASFF format (v2 disabled)"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "false"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client
    mock_securityhub = mocker.MagicMock()
    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)

    # Mock SSM client
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="RESOLVED")

    mock_securityhub.batch_update_findings.assert_called_once()
    call_args = mock_securityhub.batch_update_findings.call_args[1]
    assert "Note" in call_args
    assert call_args["Note"]["Text"] == "Test message"
    assert "Workflow" in call_args
    mock_securityhub.batch_update_findings_v2.assert_not_called()
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_productv2_format(mocker):
    """Test update_text_and_status with v2 enabled"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client
    mock_securityhub = mocker.MagicMock()
    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)

    # Mock SSM client
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="NOTIFIED")

    mock_securityhub.batch_update_findings_v2.assert_called_once()
    mock_securityhub.batch_update_findings.assert_called_once()
    call_args = mock_securityhub.batch_update_findings.call_args[1]
    assert "Note" in call_args
    assert call_args["Note"]["Text"] == "Test message"
    assert "Workflow" in call_args
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_truncates_note_over_512_chars(mocker):
    """Security Hub caps the V2 Comment and V1 Note.Text at 512 chars; a longer
    message must be truncated so the update is not rejected."""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings_v2.return_value = {"UnprocessedFindings": []}
    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    long_message = "x" * 1000
    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status(long_message, status="RESOLVED")

    v2_comment = mock_securityhub.batch_update_findings_v2.call_args[1]["Comment"]
    v1_note = mock_securityhub.batch_update_findings.call_args[1]["Note"]["Text"]
    assert len(v2_comment) == 512
    assert v2_comment.endswith("...")
    assert len(v1_note) == 512
    assert v1_note.endswith("...")
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_ocsf_format(mocker):
    """Test update_text_and_status with v2 enabled and NOTIFIED status"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client
    mock_securityhub = mocker.MagicMock()

    # Mock SSM client for Finding initialization
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="NOTIFIED")

    mock_securityhub.batch_update_findings_v2.assert_called_once()
    mock_securityhub.batch_update_findings.assert_called_once()
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


@pytest.mark.parametrize(
    "product_slug, finding_arn",
    [
        (
            "inspector",
            "arn:aws:inspector2:us-east-1:111122223333:finding/abc123",
        ),
        (
            "guardduty",
            "arn:aws:guardduty:us-east-1:111122223333:detector/d/finding/abc",
        ),
        ("macie", "arn:aws:macie2:us-east-1:111122223333:finding/abc123"),
    ],
)
def test_update_text_and_status_native_ocsf_uses_finding_info_uid(
    mocker, product_slug, finding_arn
):
    """Regression: a native OCSF finding (no top-level Id/ProductArn) must
    resolve using finding_info.uid + metadata.product.uid, not the absent
    ASFF keys. Before the fix both update calls were sent with
    Id/FindingInfoUid=None and no-op'd, leaving the finding unresolved.
    Parametrized across every OCSF-native service (Inspector 2002,
    GuardDuty/Macie 2004) to lock the per-service product-ARN normalization.
    """
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    product_v2 = f"arn:aws:securityhub:us-east-1::productv2/aws/{product_slug}"
    product_v1 = f"arn:aws:securityhub:us-east-1::product/aws/{product_slug}"
    ocsf_finding = {
        "class_uid": 2002 if product_slug == "inspector" else 2004,
        "class_name": "Vulnerability Finding",
        "finding_info": {"uid": finding_arn, "title": "t", "desc": "d"},
        "metadata": {"product": {"name": product_slug, "uid": product_v2}},
        "cloud": {"account": {"uid": "111122223333"}, "region": "us-east-1"},
        "resources": [{"uid": "resource-uid", "region": "us-east-1"}],
    }

    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings_v2.return_value = {"UnprocessedFindings": []}
    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)

    finding = findings.Finding(ocsf_finding)
    finding.update_text_and_status("Test message", status="RESOLVED")

    v2_id = mock_securityhub.batch_update_findings_v2.call_args[1][
        "FindingIdentifiers"
    ][0]
    assert v2_id["FindingInfoUid"] == finding_arn
    assert v2_id["MetadataProductUid"] == product_v2
    assert v2_id["CloudAccountUid"] == "111122223333"

    v1_id = mock_securityhub.batch_update_findings.call_args[1]["FindingIdentifiers"][0]
    assert v1_id["Id"] == finding_arn
    assert v1_id["ProductArn"] == product_v1

    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_exception_handling(mocker):
    """Test update_text_and_status exception handling"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "false"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    # Mock SecurityHub client to raise exception
    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings.side_effect = Exception("Access denied")

    # Mock SSM client for Finding initialization
    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])

    # Should not raise exception, but log warning instead
    finding.update_text_and_status("Test message", status="RESOLVED")

    mock_securityhub.batch_update_findings.assert_called_once()
    stubbed_ssm_client.deactivate()

    del os.environ["SECURITY_HUB_V2_ENABLED"]


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


def test_finding_without_product_fields(mocker):
    """Finding with no ProductFields should fall back to Compliance.SecurityControlId"""
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    finding_rec = event["detail"]["findings"][0]
    del finding_rec["ProductFields"]
    finding_rec["Compliance"]["SecurityControlId"] = "EC2.7"

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response(
        "get_parameter",
        {"Parameter": {"Value": "SC"}},
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {"Parameter": {"Value": "enabled"}},
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(finding_rec)
    assert finding.standard_name == "security-control"
    assert finding.standard_version == "2.0.0"
    assert finding.standard_control == "EC2.7"

    stubbed_ssm_client.deactivate()


def test_finding_without_product_fields_or_compliance(mocker):
    """Finding with no ProductFields and no Compliance should not crash"""
    test_data_in = open(test_data + "afsbp-ec2.7.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    finding_rec = event["detail"]["findings"][0]
    del finding_rec["ProductFields"]
    del finding_rec["Compliance"]

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response(
        "get_parameter",
        {"Parameter": {"Value": "SC"}},
    )
    stubbed_ssm_client.add_client_error(
        "get_parameter", "ParameterNotFound", "The requested parameter does not exist"
    )
    stubbed_ssm_client.add_response(
        "get_parameter",
        {"Parameter": {"Value": "enabled"}},
    )
    stubbed_ssm_client.activate()
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(finding_rec)
    assert finding.standard_name == "security-control"
    assert finding.standard_version == "2.0.0"
    assert finding.standard_control is None

    stubbed_ssm_client.deactivate()


def test_update_text_and_status_productv2_arn_replacement(mocker):
    """Test that ProductArn is converted from 'product' to 'productv2' for v2 API and kept as 'product' for v1 API"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    original_product_arn = "arn:aws:securityhub:us-east-1::product/aws/securityhub"
    event["detail"]["findings"][0]["ProductArn"] = original_product_arn

    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings_v2.return_value = {"UnprocessedFindings": []}

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="RESOLVED")

    v2_call_args = mock_securityhub.batch_update_findings_v2.call_args[1]
    v2_finding_identifier = v2_call_args["FindingIdentifiers"][0]
    assert (
        v2_finding_identifier["MetadataProductUid"]
        == "arn:aws:securityhub:us-east-1::productv2/aws/securityhub"
    )

    v1_call_args = mock_securityhub.batch_update_findings.call_args[1]
    v1_finding_identifier = v1_call_args["FindingIdentifiers"][0]
    assert v1_finding_identifier["ProductArn"] == original_product_arn

    stubbed_ssm_client.deactivate()
    del os.environ["SECURITY_HUB_V2_ENABLED"]


def test_update_text_and_status_productv2_arn_already_present(mocker):
    """Test that ProductArn with 'productv2' is kept for v2 API and converted to 'product' for v1 API"""
    os.environ["SECURITY_HUB_V2_ENABLED"] = "true"

    test_data_in = open(test_data + "CIS-1.3.json")
    event = json.loads(test_data_in.read())
    test_data_in.close()

    original_product_arn = "arn:aws:securityhub:us-east-1::productv2/aws/securityhub"
    event["detail"]["findings"][0]["ProductArn"] = original_product_arn

    mock_securityhub = mocker.MagicMock()
    mock_securityhub.batch_update_findings_v2.return_value = {"UnprocessedFindings": []}

    ssmclient = boto3.client("ssm")
    stubbed_ssm_client = Stubber(ssmclient)
    stubbed_ssm_client.add_response("get_parameter", {"Parameter": {"Value": "CIS"}})
    stubbed_ssm_client.add_client_error("get_parameter", "ParameterNotFound")
    stubbed_ssm_client.add_response(
        "get_parameter", {"Parameter": {"Value": "enabled"}}
    )
    stubbed_ssm_client.activate()

    mocker.patch("layer.sechub_findings.get_securityhub", return_value=mock_securityhub)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssmclient)

    finding = findings.Finding(event["detail"]["findings"][0])
    finding.update_text_and_status("Test message", status="RESOLVED")

    v2_call_args = mock_securityhub.batch_update_findings_v2.call_args[1]
    v2_finding_identifier = v2_call_args["FindingIdentifiers"][0]
    assert v2_finding_identifier["MetadataProductUid"] == original_product_arn

    v1_call_args = mock_securityhub.batch_update_findings.call_args[1]
    v1_finding_identifier = v1_call_args["FindingIdentifiers"][0]
    assert (
        v1_finding_identifier["ProductArn"]
        == "arn:aws:securityhub:us-east-1::product/aws/securityhub"
    )

    stubbed_ssm_client.deactivate()
    del os.environ["SECURITY_HUB_V2_ENABLED"]


# ----- OCSF + native (multi-service) ARN coverage -----


def _ocsf_event(uid: str) -> dict[str, Any]:
    """Minimal OCSF Detection finding wrapped the way send_notifications sees it."""
    return {
        "Finding": {
            "finding_info": {"uid": uid},
            "metadata": {"product": {"name": "GuardDuty"}},
        }
    }


def test_extract_finding_id_returns_ocsf_uid_when_id_missing():
    arn = "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def"
    assert findings.extract_finding_id(_ocsf_event(arn)) == arn


def test_extract_finding_id_prefers_asff_id_when_present():
    arn = "arn:aws:securityhub:us-east-1:123456789012:security-control/S3.1/finding/abc"
    event = {
        "Finding": {
            "Id": arn,
            "finding_info": {"uid": "should-not-be-used"},
        }
    }
    assert findings.extract_finding_id(event) == arn


def test_extract_finding_id_returns_empty_for_no_finding():
    assert findings.extract_finding_id({}) == ""


def test_get_control_id_from_finding_id_resolves_native_guardduty_arn():
    arn = "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def"
    assert findings.get_control_id_from_finding_id(arn) == "GuardDuty.IAMUser"


def test_get_control_id_from_finding_id_resolves_native_inspector_arn():
    arn = "arn:aws:inspector2:us-east-1:123456789012:finding/abc"
    assert (
        findings.get_control_id_from_finding_id(arn)
        == "Inspector.InstanceVulnerability"
    )


def test_get_control_id_from_finding_id_resolves_native_macie_arn():
    arn = "arn:aws:macie2:us-east-1:123456789012:finding/abc"
    assert findings.get_control_id_from_finding_id(arn) == "Macie.SensitiveDataS3Object"


def test_get_control_id_from_finding_id_resolves_native_access_analyzer_arn():
    arn = "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/org/arn:aws:kms:us-east-1:222222222222:key/abc"
    assert (
        findings.get_control_id_from_finding_id(arn)
        == "IAMAccessAnalyzer.ExternalAccess"
    )


def test_get_control_id_from_finding_id_handles_partition_variants():
    assert (
        findings.get_control_id_from_finding_id(
            "arn:aws-cn:guardduty:cn-north-1:123456789012:detector/x/finding/y"
        )
        == "GuardDuty.IAMUser"
    )
    assert (
        findings.get_control_id_from_finding_id(
            "arn:aws-us-gov:macie2:us-gov-west-1:123456789012:finding/abc"
        )
        == "Macie.SensitiveDataS3Object"
    )


def test_get_control_id_from_finding_id_returns_none_for_unknown_service():
    assert findings.get_control_id_from_finding_id("arn:aws:s3:::some-bucket") is None


def test_get_finding_type_resolves_for_ocsf_native_guardduty():
    arn = "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def"
    assert findings.get_finding_type(_ocsf_event(arn)) == "GuardDuty.IAMUser"


def test_get_finding_type_returns_empty_when_no_finding():
    assert findings.get_finding_type({}) == ""


def test_get_finding_type_falls_back_to_event_control_id_for_bare_uid():
    # Real Macie OCSF findings carry a bare-hash finding_info.uid (not a native
    # ARN) and no ASFF control id, so type resolution must fall back to the
    # orchestrator-selected event ControlId.
    event = {
        "Finding": {
            "finding_info": {"uid": "4af31f108d760df1cf5324fd1907753d"},
            "metadata": {"product": {"name": "Macie"}},
        },
        "ControlId": "Macie.SensitiveDataS3Object",
    }
    assert findings.get_finding_type(event) == "Macie.SensitiveDataS3Object"


def test_get_control_id_from_finding_id_resolves_unconsolidated_standard():
    arn = (
        "arn:aws:securityhub:us-east-1:111111111111:subscription/"
        "aws-foundational-security-best-practices/v/1.0.0/S3.1/finding/"
        "00000000-1111-2222-3333-444444444444"
    )
    assert (
        findings.get_control_id_from_finding_id(arn)
        == "aws-foundational-security-best-practices/v/1.0.0/S3.1"
    )


def test_get_control_id_from_finding_id_resolves_consolidated_standard():
    arn = (
        "arn:aws:securityhub:us-east-1:111111111111:security-control/Lambda.3/"
        "finding/00000000-1111-2222-3333-444444444444"
    )
    assert findings.get_control_id_from_finding_id(arn) == "security-control/Lambda.3"
