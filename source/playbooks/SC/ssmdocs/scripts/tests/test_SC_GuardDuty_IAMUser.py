# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: moto does not implement ssm:StartAutomationExecution or
# ssm:GetAutomationExecution (see https://docs.getmoto.org/en/latest/docs/services/ssm.html)
# or securityhub:BatchUpdateFindings. patch.object is used instead to mock
# these AWS API calls at the module boundary.
import importlib.util
import os
from typing import Callable
from unittest.mock import MagicMock, patch

import pytest

_script_dir = os.path.join(os.path.dirname(__file__), "..")
_spec = importlib.util.spec_from_file_location(
    "guardduty_module",
    os.path.join(_script_dir, "SC_GuardDuty.IAMUser.py"),
)
assert (
    _spec is not None and _spec.loader is not None
), "Failed to load SC_GuardDuty.IAMUser module spec"
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

_extract_user_name = _mod._extract_user_name
_validate_finding = _mod._validate_finding

ACCOUNT_ID = "123456789012"
USER_NAME = "compromised-user"
REGION = "us-east-1"
BUCKET_NAME = "so0111-asr-remediation-us-east-1-123456789012"

OCSF_FINDING = {
    "finding_info": {
        "uid": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def-123",
    },
    "metadata": {
        "product": {
            "uid": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
            "name": "GuardDuty",
        },
    },
    "resources": [
        {
            "uid": f"arn:aws:iam::{ACCOUNT_ID}:user/{USER_NAME}",
            "type": "AwsIamAccessKey",
            "cloud_partition": "aws",
            "region": REGION,
            "account": {"uid": ACCOUNT_ID},
        }
    ],
}


# Real Security Hub V2 OCSF Detection finding for GuardDuty IAMUser, captured
# verbatim (with redacted ids) from the live SSM execution input that the
# manual end-to-end Path B test surfaced
# (929d13d5-c2ce-4833-9cb7-05c418c3236c). Differs from the legacy fixture
# above in three places that broke the original parser:
#   - account is at ``cloud.account.uid``, not ``resources[0].account.uid``
#   - resource ``type`` is the CFN-style ``"AWS::IAM::AccessKey"``
#   - resource ``uid`` is the bare access key id (not a user ARN); the user
#     name lives under ``resources[0].user.name``
OCSF_FINDING_V2 = {
    "finding_info": {
        "uid": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/v2-789",
    },
    "metadata": {
        "product": {
            "uid": "arn:aws:securityhub:us-east-1::productv2/aws/guardduty",
            "name": "GuardDuty",
        },
    },
    "cloud": {"account": {"uid": ACCOUNT_ID}},
    "resources": [
        {
            "uid": "AKIAEXAMPLEKEYIDV2X1",
            "type": "AWS::IAM::AccessKey",
            "cloud_partition": "aws",
            "region": REGION,
            "owner": {"account": {"uid": ACCOUNT_ID}},
            "user": {"name": USER_NAME},
        }
    ],
}


def _parse_event(event: dict[str, object], context: None) -> dict[str, object]:
    # Tests assert on the result payload, so they exercise the non-raising core.
    # parse_event() wraps this and raises on FAILED (see TestParseEventRaises).
    result: dict[str, object] = _mod._execute_contain_or_restore(event, context)
    return result


class TestExtractUserName:
    def test_valid_user_arn(self):
        uid = f"arn:aws:iam::{ACCOUNT_ID}:user/{USER_NAME}"
        assert _extract_user_name(resource_uid=uid) == USER_NAME

    def test_user_with_path(self):
        uid = f"arn:aws:iam::{ACCOUNT_ID}:user/team/alice"
        assert _extract_user_name(resource_uid=uid) == "team/alice"

    def test_invalid_uid(self):
        with pytest.raises(ValueError, match="Cannot extract IAM user name"):
            _extract_user_name(resource_uid="arn:aws:iam::123456789012:role/SomeRole")

    def test_non_arn(self):
        with pytest.raises(ValueError, match="Cannot extract IAM user name"):
            _extract_user_name(resource_uid="not-an-arn")


class TestValidateFinding:
    def test_valid_finding(self):
        validated = _validate_finding(finding=OCSF_FINDING)
        assert validated.account_id == ACCOUNT_ID
        assert validated.resource_region == REGION
        assert validated.user_name == USER_NAME
        assert validated.partition == "aws"

    def test_v2_real_customer_flow(self):
        """Customer-flow regression (manual Path B surfaced this): real
        Security Hub V2 OCSF Detection finding — account from
        ``cloud.account.uid``, user name from ``resources[0].user.name``."""
        validated = _validate_finding(finding=OCSF_FINDING_V2)
        assert validated.account_id == ACCOUNT_ID
        assert validated.user_name == USER_NAME
        assert validated.resource_region == REGION
        assert validated.partition == "aws"

    def test_v2_falls_back_to_owner_when_cloud_missing(self):
        """If ``cloud.account.uid`` is absent, account id must come from
        ``resources[0].owner.account.uid`` (alternate documented location)."""
        finding = {**OCSF_FINDING_V2, "cloud": {}}
        validated = _validate_finding(finding=finding)
        assert validated.account_id == ACCOUNT_ID
        assert validated.user_name == USER_NAME

    def test_v2_resolves_user_via_iam_lookup_when_user_name_missing(self):
        """V2 OCSF customer-flow regression: when ``resources[0].user.name``
        is missing and ``resources[0].type == "AWS::IAM::AccessKey"``,
        ``_resolve_ocsf_user_name`` must resolve the owning user by calling
        ``iam:GetAccessKeyLastUsed`` against the bare access key id in
        ``resources[0].uid``. Mirrors the V2 ASFF lookup path so OCSF
        payloads that lack the optional ``user.name`` field still
        remediate (otherwise the ARN-extraction fallback would raise a
        confusing ValueError citing a malformed ARN)."""
        finding = {
            **OCSF_FINDING_V2,
            "resources": [
                {k: v for k, v in OCSF_FINDING_V2["resources"][0].items() if k != "user"}  # type: ignore[index]
            ],
        }

        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.return_value = {"UserName": USER_NAME}
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = lambda service, **kwargs: (
                fake_iam if service == "iam" else MagicMock()
            )
            validated = _validate_finding(finding=finding)

        assert validated.user_name == USER_NAME
        assert validated.account_id == ACCOUNT_ID
        fake_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAEXAMPLEKEYIDV2X1"
        )

    def test_no_resources(self):
        finding = {**OCSF_FINDING, "resources": []}
        with pytest.raises(ValueError, match="No resources found"):
            _validate_finding(finding=finding)

    def test_invalid_account_id(self):
        finding = {
            **OCSF_FINDING,
            "resources": [
                {**OCSF_FINDING["resources"][0], "account": {"uid": "bad"}}  # type: ignore[index]
            ],
        }
        with pytest.raises(ValueError, match="Invalid account ID"):
            _validate_finding(finding=finding)

    def test_invalid_region(self):
        # A crafted region must be rejected: it selects the cross-account
        # TargetLocations region for the SSM automation.
        finding = {
            **OCSF_FINDING,
            "resources": [
                {**OCSF_FINDING["resources"][0], "region": "us-east-1.attacker.com/x#"}  # type: ignore[index]
            ],
        }
        with pytest.raises(ValueError, match="Invalid region"):
            _validate_finding(finding=finding)

    def test_invalid_access_key_id(self):
        # A bare access key id from finding data must match the AKIA/ASIA
        # format before it is passed to iam:GetAccessKeyLastUsed. Drop
        # ``user.name`` so resolution falls through to the access-key lookup.
        base_resource = {
            k: v for k, v in OCSF_FINDING_V2["resources"][0].items() if k != "user"  # type: ignore[index]
        }
        finding = {
            **OCSF_FINDING_V2,
            "resources": [{**base_resource, "uid": "not-an-access-key"}],
        }
        with pytest.raises(ValueError, match="Invalid access key ID"):
            _validate_finding(finding=finding)


# --- Integration-style tests for parse_event ---


class TestParseEventValidation:
    def test_invalid_action(self):
        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "BadAction",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "Invalid Action" in str(result["message"])

    def test_empty_bucket_raises(self):
        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": "",
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "RemediationConfigBucket is required" in str(result["message"])

    def test_whitespace_bucket_raises(self):
        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": "   ",
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "RemediationConfigBucket is required" in str(result["message"])

    def test_no_resources_returns_failed(self):
        finding = {**OCSF_FINDING, "resources": []}
        result = _parse_event(
            {
                "Finding": finding,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "No resources found" in str(result["message"])

    def test_invalid_account_id_returns_failed(self):
        finding = {
            **OCSF_FINDING,
            "resources": [
                {**OCSF_FINDING["resources"][0], "account": {"uid": "bad"}}  # type: ignore[index]
            ],
        }
        result = _parse_event(
            {
                "Finding": finding,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "Invalid account ID" in str(result["message"])


class TestParseEventContain:
    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_contain_success(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        mock_invoke.return_value = "exec-12345"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = "2026/06/12/20/59/exec-12345.json"

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "SUCCESS"
        assert result["user_name"] == USER_NAME
        mock_invoke.assert_called_once()
        mock_poll.assert_called_once_with(execution_id="exec-12345")
        invoke_kwargs = mock_invoke.call_args[1]
        assert invoke_kwargs["user_name"] == USER_NAME
        assert invoke_kwargs["action"] == "Contain"
        assert invoke_kwargs["bucket_name"] == BUCKET_NAME
        # The remediation role name flows from the SSM doc input ({{
        # RemediationRoleName }}, defaulted by the runbook to
        # {solutionId}-{remediationName}-{namespace}) into the script and
        # is used for AutomationAssumeRole + ExecutionRoleName when invoking
        # AWSSupport-ContainIAMPrincipal.
        assert invoke_kwargs["remediation_role_name"] == "SO0111-GuardDuty.IAMUser-test"

        # Verify NOTIFIED status for containment (Security Hub V1 ASFF
        # Workflow.Status accepts only NEW | NOTIFIED | RESOLVED | SUPPRESSED;
        # IN_PROGRESS would be rejected as InvalidInputException).
        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["workflow_status"] == "NOTIFIED"
        assert "exec-12345" in update_kwargs["note_text"]
        # Backup key captured from the Contain run and surfaced for later rollback.
        assert result["backup_s3_key"] == "2026/06/12/20/59/exec-12345.json"
        assert "manual investigation" in update_kwargs["note_text"].lower()

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_contain_execution_failed(self, mock_invoke, mock_poll, mock_update):
        mock_invoke.return_value = "exec-fail"
        mock_poll.return_value = ("Failed", "IAM user not found")

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "FAILED"
        assert "Failed" in str(result["message"])
        assert "IAM user not found" in str(result["message"])
        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["workflow_status"] == "NOTIFIED"

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_contain_invocation_failure(self, mock_invoke, mock_update):
        from botocore.exceptions import ClientError

        mock_invoke.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "not authorized"}},
            "StartAutomationExecution",
        )

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "FAILED"
        assert "AWSSupport-ContainIAMPrincipal" in str(result["message"])
        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["workflow_status"] == "NOTIFIED"

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_polling_failure_returns_failed(self, mock_invoke, mock_poll, mock_update):
        """Polling failure path: _poll_automation_execution raises RuntimeError."""
        mock_invoke.return_value = "exec-poll-fail"
        mock_poll.side_effect = RuntimeError("Polling timed out after 600s")

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "FAILED"
        assert "Polling failed" in str(result["message"])
        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["workflow_status"] == "NOTIFIED"

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_contain_succeeds_when_backup_key_unavailable(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        """A backup-key lookup that degrades to empty must not fail Contain.

        _get_contain_backup_s3_key is self-contained: it returns "" on any
        failure (see TestGetContainBackupS3Key.test_returns_empty_on_lookup_error),
        so Contain still succeeds with an empty key.
        """
        mock_invoke.return_value = "exec-key-fail"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = ""

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        # Containment still succeeds; the backup key degrades to empty.
        assert result["status"] == "SUCCESS"
        assert result["backup_s3_key"] == ""

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_security_hub_update_failure_on_success_path(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        """Security Hub update failure on success path: result is still SUCCESS with WARNING."""
        from botocore.exceptions import ClientError

        mock_invoke.return_value = "exec-sh-fail"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = "2026/06/12/20/59/exec-sh-fail.json"
        mock_update.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ServiceUnavailableException",
                    "Message": "unavailable",
                }
            },
            "BatchUpdateFindings",
        )

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "SUCCESS"
        assert "WARNING" in str(result["message"])
        assert "Security Hub finding was NOT updated" in str(result["message"])


class TestParseEventRestore:
    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_restore_success(self, mock_invoke, mock_poll, mock_update):
        mock_invoke.return_value = "exec-restore-99"
        mock_poll.return_value = ("Success", "")

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Restore",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                "BackupS3KeyName": "2026/06/10/14/53/exec-original.json",
            },
            None,
        )

        assert result["status"] == "SUCCESS"
        invoke_kwargs = mock_invoke.call_args[1]
        assert invoke_kwargs["action"] == "Restore"
        # The exact backup key from the original Contain run flows through to
        # the runbook; the managed runbook cannot derive it.
        assert invoke_kwargs["backup_s3_key"] == "2026/06/10/14/53/exec-original.json"

        # Restore leaves the finding NOTIFIED rather than NEW so auto-remediation
        # does not immediately re-contain the principal that was just restored.
        update_kwargs = mock_update.call_args[1]
        assert update_kwargs["workflow_status"] == "NOTIFIED"
        assert "restored" in update_kwargs["note_text"].lower()

    def test_restore_without_backup_key_returns_failed(self):
        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Restore",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "BackupS3KeyName is required" in str(result["message"])

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_default_action_is_contain(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        """When Action is omitted, default is Contain."""
        mock_invoke.return_value = "exec-default"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = "2026/06/12/20/59/exec-default.json"

        result = _parse_event(
            {
                "Finding": OCSF_FINDING,
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "SUCCESS"
        invoke_kwargs = mock_invoke.call_args[1]
        assert invoke_kwargs["action"] == "Contain"


# --- ASFF input path (API-triggered remediation) ---


ASFF_FINDING = {
    "Id": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/def-123",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
    "GeneratorId": "GuardDuty.IAMUser",
    "AwsAccountId": ACCOUNT_ID,
    "Region": REGION,
    "Resources": [
        {
            "Type": "AwsIamAccessKey",
            "Id": f"arn:aws:iam::{ACCOUNT_ID}:user/{USER_NAME}",
            "Region": REGION,
        }
    ],
    "Compliance": {"Status": "FAILED", "SecurityControlId": "GuardDuty.IAMUser"},
}


# Real V2 ASFF (Security Hub auto-import path for GuardDuty IAMUser findings),
# captured verbatim (with redacted ids) from the manual end-to-end Path B test
# that surfaced this shape (SSM execution b275d4a4-cdd5-46e7-afde-c9baa0aff070).
# Differs from the legacy ASFF_FINDING above in two places that broke the
# original parser:
#   - Resources[0].Type is the CFN-style "AWS::IAM::AccessKey" (not "AwsIamAccessKey")
#   - Resources[0].Id is the bare access key id (not a user ARN); the user
#     name is not in the finding payload and must be resolved via
#     iam:GetAccessKeyLastUsed at remediation time.
ASFF_FINDING_V2 = {
    "Id": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/v2-asff-1",
    "ProductArn": "arn:aws:securityhub:us-east-1::productv2/aws/guardduty",
    "GeneratorId": "GuardDuty.IAMUser",
    "AwsAccountId": ACCOUNT_ID,
    "Region": REGION,
    "Resources": [
        {
            "Type": "AWS::IAM::AccessKey",
            "Id": "AKIAEXAMPLEKEYIDV2X1",
            "Region": REGION,
        }
    ],
    "Compliance": {"Status": "FAILED", "SecurityControlId": "GuardDuty.IAMUser"},
}


# Replayed ASFF where the normalized resource keeps Type="AwsIamAccessKey" but
# Id is an access key id prefixed with its CFN type. This is the shape the
# manual end-to-end test surfaced (the bare-access-key UID failure); the user
# is resolved via iam:GetAccessKeyLastUsed.
ASFF_FINDING_DETAILS = {
    "Id": "arn:aws:guardduty:us-east-1:123456789012:detector/abc/finding/details-1",
    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
    "GeneratorId": "GuardDuty.IAMUser",
    "AwsAccountId": ACCOUNT_ID,
    "Region": REGION,
    "Resources": [
        {
            "Type": "AwsIamAccessKey",
            "Id": "AWS::IAM::AccessKey:AKIAEXAMPLEKEYIDV2X1",
            "Region": REGION,
        }
    ],
    "Compliance": {"Status": "FAILED", "SecurityControlId": "GuardDuty.IAMUser"},
}


class TestParseEventAsff:
    """The API replays findings to the Orchestrator from the ASFF representation
    that lives in the findings table, even for multi-service GuardDuty findings
    that were originally ingested as OCSF. The runbook script must accept either
    shape on its way in."""

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_asff_contain_success(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        mock_invoke.return_value = "exec-asff-1"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = "2026/06/12/20/59/exec-asff-1.json"

        result = _parse_event(
            {
                "Finding": ASFF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )

        assert result["status"] == "SUCCESS"
        assert result["user_name"] == USER_NAME
        assert result["account_id"] == ACCOUNT_ID
        # Partition derived from the resource ARN, not from a missing
        # cloud_partition field.
        invoke_kwargs = mock_invoke.call_args[1]
        assert invoke_kwargs["partition"] == "aws"
        assert invoke_kwargs["account_id"] == ACCOUNT_ID

    def test_asff_invalid_account_id(self):
        finding = {**ASFF_FINDING, "AwsAccountId": "bad"}
        result = _parse_event(
            {
                "Finding": finding,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "Invalid account ID" in str(result["message"])

    def test_asff_invalid_region(self):
        # The region from finding data selects the cross-account SSM
        # TargetLocations region, so a malformed value must fail validation.
        finding = {
            **ASFF_FINDING,
            "Resources": [{**ASFF_FINDING["Resources"][0], "Region": "us-east-1/../evil"}],  # type: ignore[index]
        }
        result = _parse_event(
            {
                "Finding": finding,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "Invalid region" in str(result["message"])

    def test_asff_no_resources(self):
        finding = {**ASFF_FINDING, "Resources": []}
        result = _parse_event(
            {
                "Finding": finding,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "FAILED"
        assert "No resources" in str(result["message"])


class TestParseEventAsffV2:
    """V2 ASFF (Security Hub auto-import) path. The customer-flow Path B test
    surfaced this shape: Resources[0].Type = "AWS::IAM::AccessKey" with the
    bare access key id in Resources[0].Id; the user name is not in the
    payload and is resolved via iam:GetAccessKeyLastUsed at runtime.
    """

    @staticmethod
    def _boto_client_factory(fake_iam: MagicMock) -> Callable[..., MagicMock]:
        return lambda service, **kwargs: fake_iam if service == "iam" else MagicMock()

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_asff_v2_shape_resolves_user_via_iam_lookup(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        mock_invoke.return_value = "exec-asff-v2-1"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = "2026/06/17/22/40/exec-asff-v2-1.json"

        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.return_value = {"UserName": USER_NAME}
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = self._boto_client_factory(fake_iam)
            result = _parse_event(
                {
                    "Finding": ASFF_FINDING_V2,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

        assert result["status"] == "SUCCESS"
        # User name was resolved from the access key id, not the resource ARN.
        assert result["user_name"] == USER_NAME
        assert result["account_id"] == ACCOUNT_ID
        fake_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAEXAMPLEKEYIDV2X1"
        )
        invoke_kwargs = mock_invoke.call_args[1]
        assert invoke_kwargs["user_name"] == USER_NAME

    def test_asff_v2_shape_unknown_key_raises(self):
        """If GetAccessKeyLastUsed errors (NoSuchEntity, AccessDenied, etc.),
        validation must fail with a clear message and the SSM execution must
        not invoke the managed runbook with a bogus user name."""
        from botocore.exceptions import ClientError

        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchEntity",
                    "Message": "The Access Key with id AKIAEXAMPLEKEYIDV2X1 cannot be found.",
                }
            },
            "GetAccessKeyLastUsed",
        )
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = self._boto_client_factory(fake_iam)
            result = _parse_event(
                {
                    "Finding": ASFF_FINDING_V2,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

        assert result["status"] == "FAILED"
        assert "Could not resolve IAM user for access key" in str(result["message"])

    def test_asff_v2_shape_empty_username_raises(self):
        """An empty UserName response from iam:GetAccessKeyLastUsed must fail
        validation rather than silently invoke containment with an empty user."""
        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.return_value = {}
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = self._boto_client_factory(fake_iam)
            result = _parse_event(
                {
                    "Finding": ASFF_FINDING_V2,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

        assert result["status"] == "FAILED"
        assert "returned no UserName" in str(result["message"])


class TestParseEventAsffPrincipalDetails:
    """Replayed ASFF where Type stays "AwsIamAccessKey" but Id is not a user
    ARN. A CFN-type-prefixed access key id is recovered and resolved via
    iam:GetAccessKeyLastUsed."""

    @staticmethod
    def _boto_client_factory(fake_iam: MagicMock) -> Callable[..., MagicMock]:
        return lambda service, **kwargs: fake_iam if service == "iam" else MagicMock()

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_prefixed_access_key_id_resolves_via_lookup(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        mock_invoke.return_value = "exec-details-2"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = ""

        # No Details on the resource — must recover the bare access key id from
        # the CFN-type-prefixed Id and resolve the user via the IAM lookup.
        finding = {
            **ASFF_FINDING_DETAILS,
            "Resources": [
                {
                    "Type": "AwsIamAccessKey",
                    "Id": "AWS::IAM::AccessKey:AKIAEXAMPLEKEYIDV2X1",
                    "Region": REGION,
                }
            ],
        }
        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.return_value = {"UserName": USER_NAME}
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = self._boto_client_factory(fake_iam)
            result = _parse_event(
                {
                    "Finding": finding,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

        assert result["status"] == "SUCCESS"
        assert result["user_name"] == USER_NAME
        # CFN-type prefix stripped before the lookup.
        fake_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAEXAMPLEKEYIDV2X1"
        )

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_principal_name_fallback_when_lookup_fails(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        """When iam:GetAccessKeyLastUsed cannot resolve the key (deleted or
        rotated → NoSuchEntity), fall back to the principal name Security Hub
        records under Details.AwsIamAccessKey.PrincipalName."""
        from botocore.exceptions import ClientError

        mock_invoke.return_value = "exec-details-3"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = ""

        finding = {
            **ASFF_FINDING_DETAILS,
            "Resources": [
                {
                    "Type": "AWS::IAM::AccessKey",
                    "Id": "AKIAEXAMPLEKEYIDV2X1",
                    "Region": REGION,
                    "Details": {"AwsIamAccessKey": {"PrincipalName": USER_NAME}},
                }
            ],
        }
        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchEntity",
                    "Message": "The Access Key with id AKIAEXAMPLEKEYIDV2X1 cannot be found.",
                }
            },
            "GetAccessKeyLastUsed",
        )
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = self._boto_client_factory(fake_iam)
            result = _parse_event(
                {
                    "Finding": finding,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

        assert result["status"] == "SUCCESS"
        # API was tried first; PrincipalName recovered the name when it failed.
        assert result["user_name"] == USER_NAME
        fake_iam.get_access_key_last_used.assert_called_once_with(
            AccessKeyId="AKIAEXAMPLEKEYIDV2X1"
        )

    def test_lookup_failure_without_principal_name_raises(self):
        """When the API fails and no PrincipalName is recorded, the API error
        is re-raised so containment is not invoked with a bogus user."""
        from botocore.exceptions import ClientError

        finding = {
            **ASFF_FINDING_DETAILS,
            "Resources": [
                {
                    "Type": "AWS::IAM::AccessKey",
                    "Id": "AKIAEXAMPLEKEYIDV2X1",
                    "Region": REGION,
                }
            ],
        }
        fake_iam = MagicMock()
        fake_iam.get_access_key_last_used.side_effect = ClientError(
            {
                "Error": {
                    "Code": "NoSuchEntity",
                    "Message": "The Access Key with id AKIAEXAMPLEKEYIDV2X1 cannot be found.",
                }
            },
            "GetAccessKeyLastUsed",
        )
        with patch.object(_mod.boto3, "client") as mock_boto_client:
            mock_boto_client.side_effect = self._boto_client_factory(fake_iam)
            result = _parse_event(
                {
                    "Finding": finding,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

        assert result["status"] == "FAILED"
        assert "Could not resolve IAM user for access key" in str(result["message"])

    def test_restore_without_backup_key_raises(self):
        """parse_event() raises on FAILED so the SSM execution fails.

        The Orchestrator reads the SSM AutomationExecutionStatus, not the
        payload's status field, to determine remediation success.
        """
        with pytest.raises(RuntimeError, match="BackupS3KeyName is required"):
            _mod.parse_event(
                {
                    "Finding": OCSF_FINDING,
                    "Action": "Restore",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

    def test_invalid_action_raises(self):
        with pytest.raises(RuntimeError, match="Invalid Action"):
            _mod.parse_event(
                {
                    "Finding": OCSF_FINDING,
                    "Action": "BadAction",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_inner_failure_raises_after_notifying(
        self, mock_invoke, mock_poll, mock_update
    ):
        mock_invoke.return_value = "exec-fail-1"
        mock_poll.return_value = ("Failed", "containment runbook error")

        with pytest.raises(RuntimeError, match="failed with status Failed"):
            _mod.parse_event(
                {
                    "Finding": OCSF_FINDING,
                    "Action": "Contain",
                    "RemediationConfigBucket": BUCKET_NAME,
                    "SSMDocName": "test",
                    "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
                },
                None,
            )
        # Security Hub was still notified (NOTIFIED) before the raise.
        mock_update.assert_called_once()

    @patch.object(_mod, "_update_security_hub_finding")
    @patch.object(_mod, "_get_contain_backup_s3_key")
    @patch.object(_mod, "_poll_automation_execution")
    @patch.object(_mod, "_invoke_contain_iam_principal")
    def test_success_does_not_raise(
        self, mock_invoke, mock_poll, mock_backup_key, mock_update
    ):
        mock_invoke.return_value = "exec-ok-1"
        mock_poll.return_value = ("Success", "")
        mock_backup_key.return_value = "2026/06/12/20/59/exec-ok-1.json"

        result = _mod.parse_event(
            {
                "Finding": OCSF_FINDING,
                "Action": "Contain",
                "RemediationConfigBucket": BUCKET_NAME,
                "SSMDocName": "test",
                "RemediationRoleName": "SO0111-GuardDuty.IAMUser-test",
            },
            None,
        )
        assert result["status"] == "SUCCESS"


class TestGetContainBackupS3Key:
    """Extraction of the backup S3 key from the managed runbook's ReportContain output."""

    def _make_ssm(self, *, parent_steps, child_steps_by_id=None):
        """Build a mock ssm whose describe_automation_step_executions returns
        parent_steps for the polled execution and the mapped child steps for any
        resolved child execution id."""
        child_steps_by_id = child_steps_by_id or {}
        ssm = MagicMock()

        def _describe(AutomationExecutionId):
            if AutomationExecutionId in child_steps_by_id:
                return {"StepExecutions": child_steps_by_id[AutomationExecutionId]}
            return {"StepExecutions": parent_steps}

        ssm.describe_automation_step_executions.side_effect = _describe
        return ssm

    def test_extracts_key_from_child_report_message(self):
        """TargetLocations parent → child execution holds ReportContain."""
        message = (
            "### Amazon Simple Storage Service (Amazon S3) Bucket : my-bucket\n"
            "### Amazon S3 prefix : 2026/06/12/20/59/71bf0f37-40fe-4404-9bb0-2eb5e33d550c.json\n"
        )
        parent_steps = [
            {
                "StepName": "111111111111_us-east-1",
                "Outputs": {"ExecutionId": ["child-1"]},
            }
        ]
        child_steps = {
            "child-1": [
                {"StepName": "ReportContain", "Outputs": {"Message": [message]}}
            ]
        }
        ssm = self._make_ssm(parent_steps=parent_steps, child_steps_by_id=child_steps)
        with patch.object(_mod.boto3, "client", return_value=ssm):
            key = _mod._get_contain_backup_s3_key(
                execution_id="parent-1", ssm_doc_name="test"
            )
        assert key == "2026/06/12/20/59/71bf0f37-40fe-4404-9bb0-2eb5e33d550c.json"

    def test_extracts_key_without_target_locations(self):
        """Non-TargetLocations execution: ReportContain is in its own steps."""
        message = "### Amazon S3 prefix : 2026/06/12/20/59/exec-direct.json\n"
        parent_steps = [
            {"StepName": "ReportContain", "Outputs": {"Message": [message]}}
        ]
        ssm = self._make_ssm(parent_steps=parent_steps)
        with patch.object(_mod.boto3, "client", return_value=ssm):
            key = _mod._get_contain_backup_s3_key(
                execution_id="exec-1", ssm_doc_name="test"
            )
        assert key == "2026/06/12/20/59/exec-direct.json"

    def test_returns_empty_when_no_match(self):
        parent_steps = [
            {"StepName": "ReportContain", "Outputs": {"Message": ["no key here"]}}
        ]
        ssm = self._make_ssm(parent_steps=parent_steps)
        with patch.object(_mod.boto3, "client", return_value=ssm):
            assert (
                _mod._get_contain_backup_s3_key(
                    execution_id="exec-1", ssm_doc_name="test"
                )
                == ""
            )

    def test_returns_empty_when_no_report_contain_step(self):
        parent_steps = [{"StepName": "SomeOtherStep", "Outputs": {}}]
        ssm = self._make_ssm(parent_steps=parent_steps)
        with patch.object(_mod.boto3, "client", return_value=ssm):
            assert (
                _mod._get_contain_backup_s3_key(
                    execution_id="exec-1", ssm_doc_name="test"
                )
                == ""
            )

    def test_returns_empty_on_lookup_error(self):
        """Any boto failure during the lookup degrades to "" (never raises) so
        containment is not failed by an unavailable backup key."""
        from botocore.exceptions import BotoCoreError, ClientError

        for err in (
            ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}},
                "DescribeAutomationStepExecutions",
            ),
            BotoCoreError(),
        ):
            ssm = MagicMock()
            ssm.describe_automation_step_executions.side_effect = err
            with patch.object(_mod.boto3, "client", return_value=ssm):
                assert (
                    _mod._get_contain_backup_s3_key(
                        execution_id="exec-1", ssm_doc_name="test"
                    )
                    == ""
                )


class TestInvokeContainIamPrincipalParameters:
    """The parameters passed to AWSSupport-ContainIAMPrincipal differ by action.

    Restore must also re-enable the access keys Contain disabled
    (ActivateDisabledKeys=true) so a rollback fully reverses containment;
    Contain must not send BackupS3KeyName or ActivateDisabledKeys (the managed
    runbook rejects them for Contain).
    """

    def _invoke(self, *, action, backup_s3_key=""):
        captured = {}

        class _FakeSsm:
            def start_automation_execution(self, **kwargs):
                captured.update(kwargs)
                return {"AutomationExecutionId": "exec-1"}

        with patch.object(_mod.boto3, "client", return_value=_FakeSsm()):
            _mod._invoke_contain_iam_principal(
                user_name=USER_NAME,
                action=action,
                bucket_name=BUCKET_NAME,
                remediation_role_name="SO0111-GuardDuty.IAMUser-test",
                partition="aws",
                account_id=ACCOUNT_ID,
                region=REGION,
                backup_s3_key=backup_s3_key,
            )
        return captured["Parameters"]

    def test_contain_omits_restore_only_parameters(self):
        params = self._invoke(action="Contain")
        assert "BackupS3KeyName" not in params
        assert "ActivateDisabledKeys" not in params

    def test_restore_reactivates_keys_and_passes_backup_key(self):
        params = self._invoke(
            action="Restore", backup_s3_key="2026/06/13/00/44/exec.json"
        )
        assert params["BackupS3KeyName"] == ["2026/06/13/00/44/exec.json"]
        assert params["ActivateDisabledKeys"] == ["true"]
