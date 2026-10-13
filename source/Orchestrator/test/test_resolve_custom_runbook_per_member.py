# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Per-member resolution of custom runbooks.

Custom runbooks are deployed copy-per-member: every member account holds its own
SSM Automation document, and nothing is shared out of the admin account. These
tests cover what the resolver reads back from the CustomRunbookTable — the
account's own installed version — and that it never builds an owner-qualified
``{adminAccountId}:{documentName}`` reference.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Iterator

import boto3
import pytest
import resolve_ssm_doc_for_finding
from botocore.exceptions import ClientError
from moto import mock_aws
from pytest_mock import MockerFixture
from resolve_ssm_doc_for_finding import _check_custom_runbook

if TYPE_CHECKING:
    from mypy_boto3_dynamodb.service_resource import DynamoDBServiceResource, Table

TABLE_NAME = "test-custom-runbook-table"
CONTROL_ID = "S3.9"
DOCUMENT_NAME = "ASR-Custom-SC_2.0.0_S3.9"
FINDING_ACCOUNT = "111111111111"


@pytest.fixture(autouse=True)
def custom_runbook_table_env() -> Iterator[None]:
    os.environ["CUSTOM_RUNBOOK_TABLE_NAME"] = TABLE_NAME
    yield
    del os.environ["CUSTOM_RUNBOOK_TABLE_NAME"]


def _create_table() -> Table:
    # Annotated so create_table is typed as returning a Table: boto3.resource
    # itself is untyped, and the stubs only kick in from this declaration on.
    dynamodb: DynamoDBServiceResource = boto3.resource(
        "dynamodb", region_name="us-east-1"
    )
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


def _seed_runbook(
    version: int,
    deployed_accounts: dict[str, Any] | None = None,
    table: Table | None = None,
) -> Table:
    """Put one DEPLOYED runbook record. Creates the table if one isn't supplied.

    Pass an existing ``table`` to seed several records into the same table (calling
    this more than once) without the side effect of recreating it each time.
    """
    if table is None:
        table = _create_table()
    item: dict[str, Any] = {
        "runbookId": "rb-1",
        "version": version,
        "controlId": CONTROL_ID,
        "status": "DEPLOYED",
        "ssmDocumentName": DOCUMENT_NAME,
        "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
    }
    if deployed_accounts is not None:
        item["deployedAccounts"] = deployed_accounts
    table.put_item(Item=item)
    return table


@mock_aws
def test_returns_none_when_the_deployed_record_is_missing_ssm_document_name() -> None:
    # A DEPLOYED record with no ssmDocumentName is unusable: there is no document
    # to run. It must resolve to None (fall through to built-in NOTFOUND) rather
    # than returning a runbook with an empty document name.
    table = _create_table()
    table.put_item(
        Item={
            "runbookId": "rb-1",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
        }
    )

    assert _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT) is None


@mock_aws
def test_returns_none_when_the_deployed_record_is_missing_remediation_role() -> None:
    # Without a remediationRole the remediation would otherwise run under the shared
    # Orchestrator-Member role instead of the runbook's own scoped role. A record with
    # no remediationRole is treated as unusable, exactly like a missing document name.
    table = _create_table()
    table.put_item(
        Item={
            "runbookId": "rb-1",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
        }
    )

    assert _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT) is None


@mock_aws
def test_a_malformed_latest_record_does_not_hide_a_valid_older_one() -> None:
    # _select_current_deployed_runbook picks the latest-deployed record. If that
    # record is unusable (missing ssmDocumentName), an older valid record must still
    # be selected rather than the whole lookup giving up.
    table = _create_table()
    table.put_item(
        Item={
            "runbookId": "rb-broken",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            # No ssmDocumentName — unusable, and it is the latest by deployedAt.
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
            "deployedAt": "2026-05-01T00:00:00.000Z",
        }
    )
    table.put_item(
        Item={
            "runbookId": "rb-good",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
            "deployedAt": "2026-04-01T00:00:00.000Z",
        }
    )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["ssmDocumentName"] == DOCUMENT_NAME


@mock_aws
def test_a_rolled_back_version_becomes_the_active_one() -> None:
    # Deploying an older version (the documented rollback mechanism) does not demote the
    # version it replaces, so both records stay DEPLOYED. Selecting by highest version
    # would keep naming v2 current after a rollback to v1: runbookVersion would be
    # reported as 2 while v1's YAML is what the shared document actually runs, and every
    # account correctly holding v1 would be logged as drifted.
    table = _create_table()
    table.put_item(
        Item={
            "runbookId": "rb-1",
            "version": 2,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
            "deployedAt": "2026-04-01T00:00:00.000Z",
        }
    )
    table.put_item(
        Item={
            "runbookId": "rb-1",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
            # Rolled back to v1 after v2 was deployed.
            "deployedAt": "2026-05-01T00:00:00.000Z",
        }
    )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["runbookVersion"] == 1


@mock_aws
def test_the_highest_version_wins_when_no_rollback_has_happened() -> None:
    # The ordinary case must not regress: successive deploys leave the newest version
    # with the latest deployedAt, so it is still the active one.
    table = _create_table()
    for version, deployed_at in (
        (1, "2026-04-01T00:00:00.000Z"),
        (2, "2026-05-01T00:00:00.000Z"),
    ):
        table.put_item(
            Item={
                "runbookId": "rb-1",
                "version": version,
                "controlId": CONTROL_ID,
                "status": "DEPLOYED",
                "ssmDocumentName": DOCUMENT_NAME,
                "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
                "deployedAt": deployed_at,
            }
        )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["runbookVersion"] == 2


@mock_aws
def test_tolerates_a_non_numeric_member_runbook_version(mocker: MockerFixture) -> None:
    # A malformed nested runbookVersion must not crash the resolver: it falls back
    # rather than raising ValueError and failing the Step Functions execution.
    _seed_runbook(
        1,
        {FINDING_ACCOUNT: {"runbookVersion": "not-a-number", "status": "DEPLOYED"}},
    )
    warning = mocker.patch.object(resolve_ssm_doc_for_finding.logger, "warning")

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["memberRunbookVersion"] == 0
    # Not call_args: the fallback to 0 also trips the version-skew warning afterwards.
    assert any(
        "Non-numeric version value" in call.args[0] for call in warning.call_args_list
    )


@mock_aws
def test_reports_the_version_the_findings_own_account_runs() -> None:
    _seed_runbook(
        2,
        {
            FINDING_ACCOUNT: {
                "runbookVersion": 2,
                "ssmDocumentVersion": "3",
                "status": "DEPLOYED",
                "attemptedAt": "2026-01-01T00:00:00.000Z",
            }
        },
    )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["ssmDocumentName"] == DOCUMENT_NAME
    assert result["runbookVersion"] == 2
    assert result["memberRunbookVersion"] == 2
    assert result["memberStatus"] == "DEPLOYED"


@mock_aws
def test_resolves_a_plain_local_document_name_not_an_owner_qualified_one() -> None:
    # An owner-qualified reference ({admin}:{doc}) would point at the admin
    # account's copy, which is never shared under copy-per-member.
    _seed_runbook(1, {FINDING_ACCOUNT: {"runbookVersion": 1, "status": "DEPLOYED"}})

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert ":" not in result["ssmDocumentName"]
    assert result["ssmDocumentName"] == DOCUMENT_NAME


@mock_aws
def test_warns_on_version_skew_but_still_resolves_the_local_copy(
    mocker: MockerFixture,
) -> None:
    # The account was never named in the deploy that released v3, so it still
    # runs v1 — its own installed copy stays usable, the skew is just logged.
    _seed_runbook(
        3,
        {
            FINDING_ACCOUNT: {
                "runbookVersion": 1,
                "ssmDocumentVersion": "1",
                "status": "PENDING",
                "attemptedAt": "2025-12-01T00:00:00.000Z",
            }
        },
    )
    warning = mocker.patch.object(resolve_ssm_doc_for_finding.logger, "warning")

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["memberRunbookVersion"] == 1
    assert result["memberStatus"] == "PENDING"
    assert result["runbookVersion"] == 3
    assert "version skew" in warning.call_args[0][0]


@mock_aws
def test_warns_when_the_account_has_no_recorded_release(mocker: MockerFixture) -> None:
    _seed_runbook(1, {"222222222222": {"runbookVersion": 1, "status": "DEPLOYED"}})
    warning = mocker.patch.object(resolve_ssm_doc_for_finding.logger, "warning")

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["memberRunbookVersion"] is None
    assert result["memberStatus"] is None
    assert "no recorded release" in warning.call_args[0][0]


@mock_aws
def test_tolerates_a_record_with_no_member_accounts_at_all() -> None:
    # Runbooks registered before per-account tracking existed have no map.
    _seed_runbook(1)

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["memberRunbookVersion"] is None


@mock_aws
def test_returns_none_when_no_deployed_runbook_exists_for_the_control() -> None:
    _create_table()

    assert _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT) is None


@mock_aws
def test_selects_the_most_recent_deployment_when_several_are_deployed() -> None:
    # Deploying a new version does not demote the previous one, so a control can
    # hold several DEPLOYED records. The GSI sorts on `status`, which is identical
    # across them, so the query has no inherent order — without an explicit choice
    # the resolver could hand the Step Function v1 on one execution and v3 on the
    # next, silently remediating with superseded code.
    table = _create_table()
    for version in (1, 3, 2):
        table.put_item(
            Item={
                "runbookId": "rb-1",
                "version": version,
                "controlId": CONTROL_ID,
                "status": "DEPLOYED",
                "ssmDocumentName": DOCUMENT_NAME,
                "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
                "deployedAt": f"2026-01-0{version}T00:00:00.000Z",
            }
        )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["runbookVersion"] == 3


@mock_aws
def test_selects_the_later_deployment_across_separate_runbooks_for_one_control() -> (
    None
):
    # Registering without a runbook_id starts a new runbookId at v1, so one
    # control can be covered by two unrelated runbooks that are both DEPLOYED.
    # Selection still has to be deterministic across them.
    table = _create_table()
    table.put_item(
        Item={
            "runbookId": "rb-old",
            "version": 4,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
            "deployedAt": "2026-01-01T00:00:00.000Z",
        }
    )
    table.put_item(
        Item={
            "runbookId": "rb-new",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
            "deployedAt": "2026-02-01T00:00:00.000Z",
        }
    )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["runbookVersion"] == 1


@mock_aws
def test_ignores_records_whose_status_is_not_deployed() -> None:
    # The version ceiling must come from DEPLOYED records only — a higher DRAFT
    # version is staged, not released, and must never be resolved.
    table = _create_table()
    table.put_item(
        Item={
            "runbookId": "rb-1",
            "version": 1,
            "controlId": CONTROL_ID,
            "status": "DEPLOYED",
            "ssmDocumentName": DOCUMENT_NAME,
            "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
        }
    )
    table.put_item(
        Item={
            "runbookId": "rb-1",
            "version": 9,
            "controlId": CONTROL_ID,
            "status": "DRAFT",
            "ssmDocumentName": DOCUMENT_NAME,
        }
    )

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    assert result["runbookVersion"] == 1


@mock_aws
def test_raises_when_the_query_fails_rather_than_reporting_no_custom_runbook() -> None:
    """A lookup failure must propagate, never masquerade as "no custom runbook".

    `None` means "no DEPLOYED custom runbook exists", and the caller acts on that by
    falling through to a built-in that may not exist for this control. So a throttle,
    a missing ``dynamodb:Query`` grant on the GSI, or a decode failure returned as
    `None` silently discards a runbook that *is* deployed and leaves the finding
    unremediated with no signal. Nothing is created here, so the table does not exist
    and the query raises.
    """
    with pytest.raises(ClientError):
        _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)


@mock_aws
def test_reads_every_page_so_the_latest_deployment_cannot_hide_on_a_later_one(
    mocker: MockerFixture,
) -> None:
    """The winner is chosen by deployment time, so an unread page loses the winner.

    A single DynamoDB query returns at most 1 MB. Seeding many DEPLOYED records for one
    control and forcing pagination proves the loop follows `LastEvaluatedKey` — without
    it the latest deployment can be hidden on a later page. This mirrors
    `CustomRunbookRepository.findByControlId`, which paginates for the same reason.

    Forcing pagination depends on moto honoring the 1 MB page limit, so the query count
    is asserted too: if a future moto returns every item in one page, this test fails
    loudly instead of passing without ever exercising the pagination loop.
    """
    table = _create_table()
    # A large blob per item so the page limit is reached well before the last record.
    padding = "x" * 60_000
    for version in range(1, 40):
        table.put_item(
            Item={
                "runbookId": f"rb-{version}",
                "version": version,
                "controlId": CONTROL_ID,
                "status": "DEPLOYED",
                "ssmDocumentName": f"{DOCUMENT_NAME}-{version}",
                "remediationRole": "SO0111-Remediate-Custom-SC-2.0.0-S3.9",
                "deployedAt": f"2026-01-01T00:{version:02d}:00.000Z",
                "padding": padding,
            }
        )

    # Hand the resolver the very table this test seeded so its queries can be counted.
    dynamodb = mocker.Mock()
    dynamodb.Table.return_value = table
    mocker.patch.object(
        resolve_ssm_doc_for_finding, "_get_dynamodb_resource", return_value=dynamodb
    )
    query = mocker.spy(table, "query")

    result = _check_custom_runbook(CONTROL_ID, account_id=FINDING_ACCOUNT)

    assert result is not None
    # The latest timestamp is on v39 and can only be found by reading past page one.
    assert result["runbookVersion"] == 39
    assert query.call_count > 1, (
        "moto returned every record in one page, so the pagination loop was never "
        "exercised; increase the seeded record count or padding size"
    )
