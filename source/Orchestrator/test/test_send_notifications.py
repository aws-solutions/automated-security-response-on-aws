# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Unit Test: exec_ssm_doc.py
Run from /deployment/temp/source/Orchestrator after running build-s3-dist.sh
"""
from send_notifications import lambda_handler, set_message_prefix_and_suffix

event = {
    "Notification": {"State": "SUCCESS", "Message": "A Door is Ajar"},
    "SecurityStandard": "AFSBP",
    "ControlId": "foobar.1",
}


def test_resolved(mocker):
    event = {
        "Notification": {"State": "SUCCESS", "Message": "A Door is Ajar"},
        "SecurityStandard": "AFSBP",
        "ControlId": "foobar.1",
    }
    mocker.patch(
        "send_notifications.sechub_findings.SHARRNotification.notify", return_value=None
    )
    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
    assert lambda_handler(event, {}) is None


def test_wrong_standard(mocker):
    event = {
        "Notification": {"State": "WRONGSTANDARD", "Message": "A Door is Ajar"},
        "SecurityStandard": "AFSBP",
        "ControlId": "foobar.1",
    }
    mocker.patch(
        "send_notifications.sechub_findings.SHARRNotification.notify", return_value=None
    )
    mocker.patch("send_notifications.CloudWatchMetrics.send_metric", return_value=None)
    assert lambda_handler(event, {}) is None


def test_message_prefix_and_suffix():
    event = {
        "Notification": {"ExecId": "Test Prefix", "AffectedObject": "Test Suffix"},
        "SecurityStandard": "AFSBP",
        "ControlId": "foobar.1",
    }
    messagePrefix, messageSuffix = set_message_prefix_and_suffix(event)
    assert messagePrefix == "Test Prefix: "
    assert messageSuffix == " (Test Suffix)"
