# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Built-in remediations take precedence over custom runbooks.

The resolver checks the exact built-in SSM document first. Only when that comes back
``NOTFOUND`` — the built-in genuinely does not exist — is a deployed custom runbook
consulted.

These run the real handler against stubs at the AWS boundary only: SSM through a
botocore ``Stubber`` (the pattern used throughout ``test_resolve_ssm_doc_for_finding``)
and DynamoDB through moto. Nothing inside the module is stubbed, so the finding is
really parsed, the custom-runbook table is really queried, and "the custom runbook was
not consulted" is proven by a DEPLOYED record sitting in the table unused rather than
by a call assertion on our own function.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Iterator

import boto3
import pytest
from botocore.stub import Stubber
from layer.awsapi_cached_client import AWSCachedClient
from moto import mock_aws
from pytest_mock import MockerFixture
from resolve_ssm_doc_for_finding import lambda_handler

from .test_orc_utils import create_lambda_context

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource, Table

TABLE_NAME = "test-custom-runbook-table"
ACCOUNT_ID = "111111111111"
CONTROL_ID = "AutoScaling.1"
BUILTIN_DOC = "ASR-AFSBP_1.0.0_AutoScaling.1"
CUSTOM_DOC = "ASR-Custom-SC_2.0.0_AutoScaling.1"
CIS_CONTROL_ID = "1.12"
CIS_SECURITY_CONTROL_ID = "IAM.4"
CIS_BUILTIN_DOC = "ASR-CIS_1.2.0_1.12"
CIS_CUSTOM_DOC = "ASR-Custom-SC_2.0.0_IAM.4"
REGION = "us-east-1"

SHORTNAME_PARAMETER = (
    "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0/shortname"
)
CIS_SHORTNAME_PARAMETER = (
    "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/shortname"
)


@pytest.fixture(autouse=True)
def custom_runbook_table_env() -> Iterator[None]:
    os.environ["CUSTOM_RUNBOOK_TABLE_NAME"] = TABLE_NAME
    yield
    del os.environ["CUSTOM_RUNBOOK_TABLE_NAME"]


def _finding_event(event_type: str) -> dict[str, Any]:
    """An AFSBP AutoScaling.1 finding, as the state machine passes it in.

    Real ASFF shape so the handler's own ``Finding`` parsing runs — the standard,
    version and control id are derived from these fields, not injected.
    """
    return {
        "EventType": event_type,
        "Finding": {
            "Id": (
                f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:subscription/"
                "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1/finding/"
                "635ceb5d-3dfd-4458-804e-48a42cd723e4"
            ),
            "ProductArn": f"arn:aws:securityhub:{REGION}::product/aws/securityhub",
            "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1",
            "AwsAccountId": ACCOUNT_ID,
            "ProductFields": {
                "StandardsArn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0",
                "ControlId": CONTROL_ID,
                "StandardsControlArn": (
                    f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:control/"
                    "aws-foundational-security-best-practices/v/1.0.0/AutoScaling.1"
                ),
                "aws/securityhub/ProductName": "Security Hub",
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"arn:aws:autoscaling:{REGION}:{ACCOUNT_ID}:autoScalingGroup:test",
                    "Partition": "aws",
                    "Region": REGION,
                }
            ],
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        },
    }


def _unconsolidated_cis_finding_event() -> dict[str, Any]:
    """A CIS finding generated while consolidated control findings are disabled."""
    return {
        "EventType": "Security Hub Findings - Custom Action",
        "Finding": {
            "Id": (
                f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:subscription/"
                f"cis-aws-foundations-benchmark/v/1.2.0/{CIS_CONTROL_ID}/finding/"
                "3fe13eb6-b093-48b2-ba3b-b975347c3183"
            ),
            "ProductArn": f"arn:aws:securityhub:{REGION}::product/aws/securityhub",
            "GeneratorId": (
                "arn:aws:securityhub:::ruleset/"
                f"cis-aws-foundations-benchmark/v/1.2.0/rule/{CIS_CONTROL_ID}"
            ),
            "AwsAccountId": ACCOUNT_ID,
            "Compliance": {
                "SecurityControlId": CIS_SECURITY_CONTROL_ID,
                "Status": "FAILED",
            },
            "ProductFields": {
                "ControlId": CIS_CONTROL_ID,
                "StandardsArn": (
                    "arn:aws:securityhub:::standards/"
                    "cis-aws-foundations-benchmark/v/1.2.0"
                ),
                "StandardsControlArn": (
                    f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:control/"
                    f"cis-aws-foundations-benchmark/v/1.2.0/{CIS_CONTROL_ID}"
                ),
                "aws/securityhub/ProductName": "Security Hub",
            },
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"AWS::::Account:{ACCOUNT_ID}",
                    "Partition": "aws",
                    "Region": REGION,
                }
            ],
            "WorkflowState": "NEW",
            "Workflow": {"Status": "NEW"},
            "RecordState": "ACTIVE",
        },
    }


def _active_automation_document(name: str) -> dict[str, Any]:
    return {
        "Document": {
            "Name": name,
            "DocumentType": "Automation",
            "Status": "Active",
            "SchemaVersion": "0.3",
        }
    }


def _stub_standard_parameter_reads(stubber: Stubber) -> None:
    """Queue the SSM Parameter Store reads the Finding parser makes.

    Standard shortname, the (absent) control remap, then the standard's enabled flag.
    """
    stubber.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": SHORTNAME_PARAMETER,
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
            }
        },
        {"Name": SHORTNAME_PARAMETER},
    )
    stubber.add_client_error("get_parameter", "ParameterNotFound")
    stubber.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
            }
        },
    )


def _stub_cis_standard_parameter_reads(stubber: Stubber) -> None:
    stubber.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": CIS_SHORTNAME_PARAMETER,
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
            }
        },
        {"Name": CIS_SHORTNAME_PARAMETER},
    )
    stubber.add_client_error(
        "get_parameter",
        "ParameterNotFound",
        expected_params={"Name": f"/Solutions/SO0111/CIS/1.2.0/{CIS_CONTROL_ID}/remap"},
    )
    status_parameter = "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0/status"
    stubber.add_response(
        "get_parameter",
        {
            "Parameter": {
                "Name": status_parameter,
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
            }
        },
        {"Name": status_parameter},
    )


@pytest.fixture
def ssm_stubber(mocker: MockerFixture) -> Iterator[Stubber]:
    """A stubbed SSM client wired in wherever the handler reaches for one.

    The client factory is the injection seam: the stub itself sits at the botocore
    boundary, so document state and parameter reads come from queued API responses
    rather than from patched internal functions.
    """
    ssm_client = AWSCachedClient(REGION).get_connection("ssm")
    stubber = Stubber(ssm_client)
    _stub_standard_parameter_reads(stubber)
    mocker.patch("resolve_ssm_doc_for_finding._get_ssm_client", return_value=ssm_client)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssm_client)
    yield stubber
    stubber.deactivate()


@pytest.fixture
def cis_ssm_stubber(mocker: MockerFixture) -> Iterator[Stubber]:
    ssm_client = AWSCachedClient(REGION).get_connection("ssm")
    stubber = Stubber(ssm_client)
    _stub_cis_standard_parameter_reads(stubber)
    mocker.patch("resolve_ssm_doc_for_finding._get_ssm_client", return_value=ssm_client)
    mocker.patch("layer.sechub_findings.get_ssm_connection", return_value=ssm_client)
    yield stubber
    stubber.deactivate()


def _create_table() -> Table:
    # Annotated so create_table is typed as returning a Table: boto3.resource
    # itself is untyped, and the stubs only kick in from this declaration on.
    dynamodb: DynamoDBServiceResource = boto3.resource("dynamodb", region_name=REGION)
    return dynamodb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "runbookId", "KeyType": "HASH"},
            {"AttributeName": "version", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "runbookId", "AttributeType": "S"},
            {"AttributeName": "version", "AttributeType": "N"},
            {"AttributeName": "controlId", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "controlId-status-index",
                "KeySchema": [
                    {"AttributeName": "controlId", "KeyType": "HASH"},
                    {"AttributeName": "status", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _seed_deployed_custom_runbook(
    *, control_id: str = CONTROL_ID, document_name: str = CUSTOM_DOC
) -> None:
    """A DEPLOYED custom runbook for the requested security control."""
    _create_table().put_item(
        Item={
            "runbookId": "rb-1",
            "version": 1,
            "controlId": control_id,
            "status": "DEPLOYED",
            "ssmDocumentName": document_name,
            "remediationRole": "SO0111-Remediate-Custom",
            "deployedAccounts": {
                ACCOUNT_ID: {"runbookVersion": 1, "status": "DEPLOYED"}
            },
        }
    )


@mock_aws
def test_active_builtin_is_used_and_custom_runbook_is_never_consulted(
    ssm_stubber: Stubber,
) -> None:
    # A custom runbook for this very control is DEPLOYED and would resolve if it were
    # consulted. An ACTIVE built-in must win anyway, and only the built-in document's
    # state is checked — the stubber queues exactly one describe_document, so a second
    # one would fail the test.
    _seed_deployed_custom_runbook()
    ssm_stubber.add_response(
        "describe_document",
        _active_automation_document(BUILTIN_DOC),
        {"Name": BUILTIN_DOC},
    )
    ssm_stubber.activate()

    result = lambda_handler(
        _finding_event("Security Hub Findings - Custom Action"), create_lambda_context()
    )

    assert result["status"] == "ACTIVE"
    assert result["automationdocid"] == BUILTIN_DOC
    ssm_stubber.assert_no_pending_responses()


@mock_aws
def test_missing_builtin_falls_through_to_a_deployed_custom_runbook(
    ssm_stubber: Stubber,
) -> None:
    # Built-in does not exist, the custom document does → the custom runbook is used.
    _seed_deployed_custom_runbook()
    ssm_stubber.add_client_error("describe_document", "InvalidDocument")
    ssm_stubber.add_response(
        "describe_document",
        _active_automation_document(CUSTOM_DOC),
        {"Name": CUSTOM_DOC},
    )
    ssm_stubber.activate()

    result = lambda_handler(
        _finding_event("Security Hub Findings - Custom Action"), create_lambda_context()
    )

    assert result["status"] == "ACTIVE"
    assert result["automationdocid"] == CUSTOM_DOC
    assert result["remediationrole"] == "SO0111-Remediate-Custom"


@mock_aws
def test_unconsolidated_standard_finding_resolves_canonical_custom_runbook(
    cis_ssm_stubber: Stubber,
) -> None:
    _seed_deployed_custom_runbook(
        control_id=CIS_SECURITY_CONTROL_ID, document_name=CIS_CUSTOM_DOC
    )
    cis_ssm_stubber.add_client_error(
        "describe_document",
        "InvalidDocument",
        expected_params={"Name": CIS_BUILTIN_DOC},
    )
    cis_ssm_stubber.add_response(
        "describe_document",
        _active_automation_document(CIS_CUSTOM_DOC),
        {"Name": CIS_CUSTOM_DOC},
    )
    cis_ssm_stubber.activate()

    result = lambda_handler(
        _unconsolidated_cis_finding_event(), create_lambda_context()
    )

    assert result["status"] == "ACTIVE"
    assert result["controlid"] == CIS_CONTROL_ID
    assert result["automationdocid"] == CIS_CUSTOM_DOC
    assert result["remediationrole"] == "SO0111-Remediate-Custom"
    cis_ssm_stubber.assert_no_pending_responses()


@mock_aws
def test_custom_runbook_registered_under_standard_specific_id_still_resolves(
    cis_ssm_stubber: Stubber, caplog: pytest.LogCaptureFixture
) -> None:
    """A record keyed the old way (CIS 1.12, not IAM.4) must not go dark.

    Before the lookup used the canonical id it queried the standard-specific id,
    so such records exist in deployed tables. They resolve on a second query and
    are called out so the operator can re-register them.
    """
    _seed_deployed_custom_runbook(
        control_id=CIS_CONTROL_ID, document_name=CIS_CUSTOM_DOC
    )
    cis_ssm_stubber.add_client_error(
        "describe_document",
        "InvalidDocument",
        expected_params={"Name": CIS_BUILTIN_DOC},
    )
    cis_ssm_stubber.add_response(
        "describe_document",
        _active_automation_document(CIS_CUSTOM_DOC),
        {"Name": CIS_CUSTOM_DOC},
    )
    cis_ssm_stubber.activate()

    result = lambda_handler(
        _unconsolidated_cis_finding_event(), create_lambda_context()
    )

    assert result["status"] == "ACTIVE"
    assert result["automationdocid"] == CIS_CUSTOM_DOC
    assert (
        f"registered under standard-specific controlId={CIS_CONTROL_ID}" in caplog.text
    )
    assert f"canonical controlId={CIS_SECURITY_CONTROL_ID}" in caplog.text
    cis_ssm_stubber.assert_no_pending_responses()


@mock_aws
def test_missing_builtin_and_no_custom_reports_builtin_notfound(
    ssm_stubber: Stubber,
) -> None:
    # The table exists but holds no DEPLOYED record for this control, so the built-in
    # NOTFOUND is reported rather than any custom document's state.
    _create_table()
    ssm_stubber.add_client_error("describe_document", "InvalidDocument")
    ssm_stubber.activate()

    result = lambda_handler(
        _finding_event("Security Hub Findings - Custom Action"), create_lambda_context()
    )

    assert result["status"] == "NOTFOUND"
    assert result["automationdocid"] == BUILTIN_DOC


@mock_aws
def test_an_automated_trigger_never_consults_a_custom_runbook(
    ssm_stubber: Stubber,
) -> None:
    # Custom runbooks are manual-trigger only. Even with a DEPLOYED custom runbook for
    # this control, an automatically-triggered finding must report the built-in
    # NOTFOUND without ever querying the custom-runbook table — so a table throttle or
    # access error cannot fail an automatic execution. Only the built-in
    # describe_document is queued; a custom-document lookup would fail the test.
    _seed_deployed_custom_runbook()
    ssm_stubber.add_client_error("describe_document", "InvalidDocument")
    ssm_stubber.activate()

    result = lambda_handler(
        _finding_event("Security Hub Findings - Imported"), create_lambda_context()
    )

    assert result["status"] == "NOTFOUND"
    assert result["automationdocid"] == BUILTIN_DOC
    ssm_stubber.assert_no_pending_responses()


@mock_aws
def test_a_resolved_but_unusable_custom_runbook_reports_its_own_state_naming_the_doc(
    ssm_stubber: Stubber,
) -> None:
    # Built-in missing, custom runbook deployed but its document is stuck Updating. The
    # operator must see the custom document's real state and a message naming that
    # document — not a built-in NOTFOUND that reads as "ASR ships no remediation for
    # this control".
    _seed_deployed_custom_runbook()
    ssm_stubber.add_client_error("describe_document", "InvalidDocument")
    ssm_stubber.add_response(
        "describe_document",
        {
            "Document": {
                "Name": CUSTOM_DOC,
                "DocumentType": "Automation",
                "Status": "Updating",
                "SchemaVersion": "0.3",
            }
        },
        {"Name": CUSTOM_DOC},
    )
    ssm_stubber.activate()

    result = lambda_handler(
        _finding_event("Security Hub Findings - Custom Action"), create_lambda_context()
    )

    assert result["status"] == "NOTACTIVE"
    assert CUSTOM_DOC in result["message"]
