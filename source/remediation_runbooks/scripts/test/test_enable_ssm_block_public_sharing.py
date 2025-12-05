# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import sys
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

sys.path.append("..")
with patch("boto3.client"):
    import enable_ssm_block_public_sharing as remediation


@pytest.fixture
def ssm_client():
    return MagicMock()


@pytest.fixture
def event():
    return {"account_id": "123456789012"}


def test_lambda_handler_already_enabled(ssm_client, event):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        ssm_client.get_service_setting.return_value = {
            "ServiceSetting": {"SettingValue": "Disable"}
        }

        result = remediation.lambda_handler(event, None)

        assert result["response"]["status"] == "NO_CHANGE_REQUIRED"
        assert result["response"]["setting_value"] == "Disable"
        ssm_client.update_service_setting.assert_not_called()


def test_lambda_handler_enable_success(ssm_client, event):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        # First call returns "Enable", second call returns "Disable" (after update)
        ssm_client.get_service_setting.side_effect = [
            {"ServiceSetting": {"SettingValue": "Enable"}},
            {"ServiceSetting": {"SettingValue": "Disable"}},
        ]

        result = remediation.lambda_handler(event, None)

        assert result["response"]["status"] == "SUCCESS"
        assert result["response"]["setting_value"] == "Disable"
        ssm_client.update_service_setting.assert_called_once_with(
            SettingId="/ssm/documents/console/public-sharing-permission",
            SettingValue="Disable",
        )


def test_lambda_handler_verification_fails(ssm_client, event):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        # Both calls return "Enable" (update didn't work)
        ssm_client.get_service_setting.side_effect = [
            {"ServiceSetting": {"SettingValue": "Enable"}},
            {"ServiceSetting": {"SettingValue": "Enable"}},
        ]

        with pytest.raises(RuntimeError, match="Failed to verify setting change"):
            remediation.lambda_handler(event, None)


def test_get_service_setting_success(ssm_client):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        ssm_client.get_service_setting.return_value = {
            "ServiceSetting": {"SettingValue": "Disable"}
        }

        result = remediation.get_service_setting(ssm_client)

        assert result == "Disable"
        ssm_client.get_service_setting.assert_called_once_with(
            SettingId="/ssm/documents/console/public-sharing-permission"
        )


def test_get_service_setting_error(ssm_client):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        ssm_client.get_service_setting.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "GetServiceSetting",
        )

        with pytest.raises(RuntimeError, match="Failed to get service setting"):
            remediation.get_service_setting(ssm_client)


def test_update_service_setting_success(ssm_client):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        remediation.update_service_setting(ssm_client)

        ssm_client.update_service_setting.assert_called_once_with(
            SettingId="/ssm/documents/console/public-sharing-permission",
            SettingValue="Disable",
        )


def test_update_service_setting_error(ssm_client):
    with patch.object(remediation, "connect_to_ssm", return_value=ssm_client):
        ssm_client.update_service_setting.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "UpdateServiceSetting",
        )

        with pytest.raises(RuntimeError, match="Failed to update service setting"):
            remediation.update_service_setting(ssm_client)


def test_lambda_handler_missing_account_id():
    event = {}

    with pytest.raises(Exception):
        remediation.lambda_handler(event, None)
