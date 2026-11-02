# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Literal
from unittest.mock import MagicMock, patch

import pytest
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
)
from botocore.exceptions import EndpointConnectionError
from botocore.stub import Stubber
from cfnresponse import FAILED, SUCCESS
from mypy_boto3_cloudformation.literals import StackStatusType
from playbook_selection_validator import (
    CLOUDFORMATION_CLIENT,
    PHYSICAL_RESOURCE_ID,
    SECURITY_HUB_CLIENT,
    ControlFindingGenerator,
    YesNo,
    lambda_handler,
)

STACK_ID = "arn:aws:cloudformation:us-east-1:111111111111:stack/ASR-Admin/guid"
HUB_ARN = "arn:aws:securityhub:us-east-1:111111111111:hub/default"

RequestType = Literal["Create", "Update", "Delete"]


def build_event(
    request_type: RequestType,
    security_control_playbook_selected: str,
    *,
    standard_playbook_selected: YesNo = "no",
    security_hub_required: YesNo = "yes",
) -> dict[str, Any]:
    return {
        "RequestType": request_type,
        "StackId": STACK_ID,
        "ResponseURL": "https://example.com/response",
        "ResourceProperties": {
            "SecurityControlPlaybookSelected": security_control_playbook_selected,
            "StandardPlaybookSelected": standard_playbook_selected,
            "SecurityHubRequired": security_hub_required,
        },
    }


def invoke(event: dict[str, Any]) -> None:
    lambda_handler(CloudFormationCustomResourceEvent(event), MagicMock())


@pytest.fixture
def cloudformation_stub() -> Iterator[Stubber]:
    with Stubber(CLOUDFORMATION_CLIENT) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


@pytest.fixture
def security_hub_stub() -> Iterator[Stubber]:
    with Stubber(SECURITY_HUB_CLIENT) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


@pytest.fixture
def send_response() -> Iterator[MagicMock]:
    with patch("cfnresponse.send") as mock_send:
        yield mock_send


def stub_stack_status(stubber: Stubber, status: StackStatusType) -> None:
    stubber.add_response(
        "describe_stacks",
        {
            "Stacks": [
                {
                    "StackName": "ASR-Admin",
                    "StackId": STACK_ID,
                    "CreationTime": "2026-01-01T00:00:00Z",
                    "StackStatus": status,
                }
            ]
        },
        {"StackName": STACK_ID},
    )


def stub_control_finding_generator(
    stubber: Stubber, generator: ControlFindingGenerator
) -> None:
    stubber.add_response(
        "describe_hub",
        {"HubArn": HUB_ARN, "ControlFindingGenerator": generator},
        {},
    )


def get_sent_status_and_reason(send_response: MagicMock) -> tuple[str, str | None]:
    send_response.assert_called_once()
    _event, _context, status, _data, physical_resource_id = send_response.call_args.args
    assert physical_resource_id == PHYSICAL_RESOURCE_ID
    return status, send_response.call_args.kwargs.get("reason")


@pytest.mark.parametrize("request_type", ["Create", "Update"])
@pytest.mark.parametrize(
    "security_control_selection, standard_selection, generator",
    [
        ("yes", "no", "SECURITY_CONTROL"),
        ("no", "yes", "STANDARD_CONTROL"),
        # SC alongside standard playbooks still remediates in either setting, so it only warns.
        ("yes", "yes", "SECURITY_CONTROL"),
        ("yes", "yes", "STANDARD_CONTROL"),
    ],
)
def test_selection_that_remediates_succeeds(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
    request_type: RequestType,
    security_control_selection: YesNo,
    standard_selection: YesNo,
    generator: ControlFindingGenerator,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "UPDATE_IN_PROGRESS")
    stub_control_finding_generator(security_hub_stub, generator)

    # ACT
    invoke(
        build_event(
            request_type,
            security_control_selection,
            standard_playbook_selected=standard_selection,
        )
    )

    # ASSERT
    assert get_sent_status_and_reason(send_response) == (SUCCESS, None)


@pytest.mark.parametrize("request_type", ["Create", "Update"])
# The Member stack does not require Security Hub, but must still reject a selection that cannot remediate.
@pytest.mark.parametrize("security_hub_required", ["yes", "no"])
@pytest.mark.parametrize(
    "security_control_selection, standard_selection, generator, expected_phrases",
    [
        (
            "no",
            "yes",
            "SECURITY_CONTROL",
            ["turned on", "SECURITY_CONTROL", "SC) playbook parameter to yes"],
        ),
        (
            "yes",
            "no",
            "STANDARD_CONTROL",
            ["turned off", "STANDARD_CONTROL", "each security standard enabled"],
        ),
    ],
)
def test_selection_that_cannot_remediate_fails_with_fix(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
    request_type: RequestType,
    security_hub_required: YesNo,
    security_control_selection: YesNo,
    standard_selection: YesNo,
    generator: ControlFindingGenerator,
    expected_phrases: list[str],
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")
    stub_control_finding_generator(security_hub_stub, generator)

    # ACT
    invoke(
        build_event(
            request_type,
            security_control_selection,
            standard_playbook_selected=standard_selection,
            security_hub_required=security_hub_required,
        )
    )

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    for phrase in expected_phrases:
        assert phrase in reason


@pytest.mark.parametrize(
    "stack_status", ["UPDATE_ROLLBACK_IN_PROGRESS", "ROLLBACK_IN_PROGRESS"]
)
def test_rollback_succeeds_without_reading_security_hub_or_properties(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
    stack_status: StackStatusType,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, stack_status)
    event_from_older_template = build_event("Update", "no")
    del event_from_older_template["ResourceProperties"]["StandardPlaybookSelected"]

    # ACT
    invoke(event_from_older_template)

    # ASSERT
    assert get_sent_status_and_reason(send_response) == (SUCCESS, None)


def test_unreadable_stack_status_still_validates(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ARRANGE
    cloudformation_stub.add_client_error(
        "describe_stacks", service_error_code="AccessDenied"
    )
    stub_control_finding_generator(security_hub_stub, "SECURITY_CONTROL")

    # ACT
    invoke(build_event("Update", "no"))

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    assert "turned on" in reason


def test_delete_succeeds_without_any_call(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ACT
    invoke(build_event("Delete", "not-a-selection"))

    # ASSERT
    assert get_sent_status_and_reason(send_response) == (SUCCESS, None)


def test_security_hub_not_enabled_fails_with_instruction_when_required(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")
    security_hub_stub.add_client_error(
        "describe_hub", service_error_code="InvalidAccessException"
    )

    # ACT
    invoke(build_event("Create", "yes", security_hub_required="yes"))

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    assert "Enable Security Hub before deploying ASR" in reason


def test_security_hub_not_enabled_succeeds_when_not_required(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")
    security_hub_stub.add_client_error(
        "describe_hub", service_error_code="InvalidAccessException"
    )

    # ACT
    invoke(build_event("Create", "yes", security_hub_required="no"))

    # ASSERT
    assert get_sent_status_and_reason(send_response) == (SUCCESS, None)


def test_other_security_hub_error_fails_with_error_text(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")
    security_hub_stub.add_client_error(
        "describe_hub",
        service_error_code="ThrottlingException",
        service_message="Rate exceeded",
    )

    # ACT
    invoke(build_event("Create", "yes"))

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    assert "ThrottlingException" in reason
    assert "Rate exceeded" in reason


def test_security_hub_unreachable_fails_with_settings_message(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")

    # ACT
    with patch.object(
        SECURITY_HUB_CLIENT,
        "describe_hub",
        side_effect=EndpointConnectionError(endpoint_url="https://securityhub"),
    ):
        invoke(build_event("Create", "yes"))

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    assert reason.startswith("Could not read the Security Hub settings")


@pytest.mark.parametrize(
    "property_name",
    [
        "SecurityControlPlaybookSelected",
        "StandardPlaybookSelected",
        "SecurityHubRequired",
    ],
)
def test_invalid_property_fails_naming_the_property(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
    property_name: str,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")
    event = build_event("Create", "yes")
    event["ResourceProperties"][property_name] = "maybe"

    # ACT
    invoke(event)

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    assert property_name in reason
    assert "'maybe'" in reason


def test_unexpected_error_still_answers_cloudformation(
    cloudformation_stub: Stubber,
    security_hub_stub: Stubber,
    send_response: MagicMock,
) -> None:
    # ARRANGE
    stub_stack_status(cloudformation_stub, "CREATE_IN_PROGRESS")
    malformed_event = build_event("Create", "yes")
    del malformed_event["ResourceProperties"]

    # ACT
    invoke(malformed_event)

    # ASSERT
    status, reason = get_sent_status_and_reason(send_response)
    assert status == FAILED
    assert reason is not None
    assert "unexpectedly" in reason
