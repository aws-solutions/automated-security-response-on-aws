# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared constants for ASR custom-action names propagated through the orchestrator.

These values mirror ``ASR_ACTION_NAMES`` in
``source/data-models/apiActions.ts``. The API Lambda emits the action name in
``detail.actionName``; the event transformer copies it to
``event["CustomActionName"]``; ``send_notifications.lambda_handler`` reads it
to detect rollback completions and persist the rollback lifecycle status
(``ROLLBACK_SUCCESS`` / ``ROLLBACK_FAILED``).

IMPORTANT: keep these strings in sync with the TypeScript constants. A
mismatch silently turns a rollback into a regular SUCCESS overwrite.
"""
from typing import Final

CUSTOM_ACTION_NAME_REMEDIATE: Final[str] = "Remediate with ASR"
CUSTOM_ACTION_NAME_REMEDIATE_AND_TICKET: Final[str] = "ASR:Remediate&Ticket"
CUSTOM_ACTION_NAME_ROLLBACK: Final[str] = "ASR:Rollback"
