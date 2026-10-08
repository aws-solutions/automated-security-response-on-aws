# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`_add_doc_state_to_answer` must report the state it actually found.

Each failing check used to set its status and then fall through to an unconditional
``answer.update({"status": "ACTIVE"})``, which overwrote it. Every caller therefore saw
ACTIVE regardless — so the "fall back to built-in when the custom document is not
Active" branch could never run, and the orchestrator would go on to execute a document
that was not Active, or not even an Automation document.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import resolve_ssm_doc_for_finding
from layer.utils import StepFunctionLambdaAnswer
from resolve_ssm_doc_for_finding import _add_doc_state_to_answer

# The real answer object is used rather than a stand-in: it is an in-memory object with
# no external dependencies, and its update() filters through an allowlist. A local
# reimplementation of update() would keep passing while production diverged from it.


def _ssm_returning(document: dict[str, Any]) -> MagicMock:
    client = MagicMock()
    client.describe_document.return_value = {"Document": document}
    return client


def test_reports_notactive_for_a_document_that_is_not_active() -> None:
    answer = StepFunctionLambdaAnswer()
    with patch.object(
        resolve_ssm_doc_for_finding,
        "_get_ssm_client",
        return_value=_ssm_returning(
            {"DocumentType": "Automation", "Status": "Updating"}
        ),
    ):
        _add_doc_state_to_answer("ASR-Custom-Doc", "111111111111", "us-east-1", answer)

    assert answer.status == "NOTACTIVE"
    assert "Updating" in answer.message


def test_reports_error_for_a_document_that_is_not_an_automation() -> None:
    answer = StepFunctionLambdaAnswer()
    with patch.object(
        resolve_ssm_doc_for_finding,
        "_get_ssm_client",
        return_value=_ssm_returning({"DocumentType": "Command", "Status": "Active"}),
    ):
        _add_doc_state_to_answer("ASR-Custom-Doc", "111111111111", "us-east-1", answer)

    assert answer.status == "ERROR"
    assert "Command" in answer.message


def test_reports_active_only_when_the_document_really_is() -> None:
    answer = StepFunctionLambdaAnswer()
    with patch.object(
        resolve_ssm_doc_for_finding,
        "_get_ssm_client",
        return_value=_ssm_returning({"DocumentType": "Automation", "Status": "Active"}),
    ):
        _add_doc_state_to_answer("ASR-Custom-Doc", "111111111111", "us-east-1", answer)

    assert answer.status == "ACTIVE"
