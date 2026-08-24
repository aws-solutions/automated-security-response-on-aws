# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for migration_auto_remediation_provider."""

from typing import Any, cast
from unittest.mock import MagicMock, patch

import boto3
import pytest
from aws_lambda_powertools.utilities.data_classes import (
    CloudFormationCustomResourceEvent,
)
from migration_auto_remediation_provider import (
    NOTIFICATION_TOPIC_ARN_ENV,
    discover_enabled_v2_rules,
    extract_control_id_from_rule_name,
    lambda_handler,
    notify_migration_failure,
    validate_event,
    write_enabled_controls_to_table,
)
from moto import mock_aws


class TestExtractControlIdFromRuleName:
    """Tests for extract_control_id_from_rule_name parsing logic.

    Rule names follow {securityStandard}_{securityStandardVersion}_{controlId}_AutoTrigger
    (see v2.x source/lib/ssmplaybook.ts Trigger). The seven supported v2 prefix
    strings, derived from the v2.3.0 playbook configs, are:

        SC, AFSBP, NIST80053R5, PCI, CIS (1.2.0/1.4.0/3.0.0)
    """

    # ---- SC standard (control IDs are already Security Control IDs) ----

    def test_sc_rule(self):
        assert extract_control_id_from_rule_name("SC_2.0.0_S3.5_AutoTrigger") == "S3.5"

    def test_sc_cloudtrail_control(self):
        assert (
            extract_control_id_from_rule_name("SC_2.0.0_CloudTrail.1_AutoTrigger")
            == "CloudTrail.1"
        )

    def test_sc_cloudwatch_control(self):
        assert (
            extract_control_id_from_rule_name("SC_2.0.0_CloudWatch.16_AutoTrigger")
            == "CloudWatch.16"
        )

    # ---- AFSBP standard (control IDs are already Security Control IDs) ----

    def test_afsbp_rule(self):
        assert (
            extract_control_id_from_rule_name("AFSBP_1.0.0_S3.5_AutoTrigger") == "S3.5"
        )

    def test_afsbp_iam_control(self):
        assert (
            extract_control_id_from_rule_name("AFSBP_1.0.0_IAM.7_AutoTrigger")
            == "IAM.7"
        )

    # ---- NIST80053R5 standard (control IDs are already Security Control IDs) ----

    def test_nist_rule(self):
        assert (
            extract_control_id_from_rule_name(
                "NIST80053R5_5.0.0_CloudTrail.1_AutoTrigger"
            )
            == "CloudTrail.1"
        )

    # ---- PCI standard (strip "PCI." prefix) ----

    def test_pci_rule_strips_prefix(self):
        assert (
            extract_control_id_from_rule_name("PCI_3.2.1_PCI.S3.5_AutoTrigger")
            == "S3.5"
        )

    def test_pci_rule_iam_strips_prefix(self):
        assert (
            extract_control_id_from_rule_name("PCI_3.2.1_PCI.IAM.7_AutoTrigger")
            == "IAM.7"
        )

    # ---- Legacy control-id aliasing (post-translation) ----

    def test_afsbp_elbv2_aliased_to_elb(self):
        # AFSBP ships ELBv2.1; v3+ ships it as ELB.1
        assert (
            extract_control_id_from_rule_name("AFSBP_1.0.0_ELBv2.1_AutoTrigger")
            == "ELB.1"
        )

    def test_pci_elbv2_aliased_to_elb(self):
        # PCI prefix-strip + alias chain: PCI.ELBv2.1 -> ELBv2.1 -> ELB.1
        assert (
            extract_control_id_from_rule_name("PCI_3.2.1_PCI.ELBv2.1_AutoTrigger")
            == "ELB.1"
        )

    # ---- CIS v1.2.0 (lookup table) ----

    def test_cis120_password_policy_maps_to_iam_7(self):
        # ASR consolidates all CIS v1.2.0 password-policy rules to SetIAMPasswordPolicy (SC IAM.7).
        assert extract_control_id_from_rule_name("CIS_1.2.0_1.5_AutoTrigger") == "IAM.7"

    def test_cis120_support_role_maps_to_iam_18(self):
        assert (
            extract_control_id_from_rule_name("CIS_1.2.0_1.20_AutoTrigger") == "IAM.18"
        )

    def test_cis120_default_sg_maps_to_ec2_2(self):
        assert extract_control_id_from_rule_name("CIS_1.2.0_4.3_AutoTrigger") == "EC2.2"

    def test_cis120_unmapped_returns_none(self):
        # CIS v1.2.0 4.2 (port 3389) has no ASR remediation -> not in lookup
        assert extract_control_id_from_rule_name("CIS_1.2.0_4.2_AutoTrigger") is None

    # ---- CIS v1.4.0 (lookup table) ----

    def test_cis140_support_role_maps_to_iam_18(self):
        assert (
            extract_control_id_from_rule_name("CIS_1.4.0_1.17_AutoTrigger") == "IAM.18"
        )

    def test_cis140_dotted_id_maps_to_s3_5(self):
        assert (
            extract_control_id_from_rule_name("CIS_1.4.0_2.1.2_AutoTrigger") == "S3.5"
        )

    def test_cis140_dotted_id_maps_to_s3_1(self):
        assert (
            extract_control_id_from_rule_name("CIS_1.4.0_2.1.5.1_AutoTrigger") == "S3.1"
        )

    def test_cis140_unmapped_returns_none(self):
        assert extract_control_id_from_rule_name("CIS_1.4.0_99.99_AutoTrigger") is None

    # ---- CIS v3.0.0 (lookup table) ----

    def test_cis300_iam_3(self):
        assert (
            extract_control_id_from_rule_name("CIS_3.0.0_1.14_AutoTrigger") == "IAM.3"
        )

    def test_cis300_dotted_id(self):
        assert (
            extract_control_id_from_rule_name("CIS_3.0.0_2.1.4.1_AutoTrigger") == "S3.1"
        )

    def test_cis300_rds_13(self):
        assert (
            extract_control_id_from_rule_name("CIS_3.0.0_2.3.2_AutoTrigger") == "RDS.13"
        )

    def test_cis_unknown_version_returns_none(self):
        # CIS without a known version mapping -> None
        assert extract_control_id_from_rule_name("CIS_2.0.0_1.5_AutoTrigger") is None

    # ---- malformed / unknown rules ----

    def test_unknown_standard_returns_none(self):
        assert extract_control_id_from_rule_name("HIPAA_1.0.0_S3.5_AutoTrigger") is None

    def test_missing_suffix_returns_none(self):
        assert extract_control_id_from_rule_name("SC_2.0.0_S3.5") is None

    def test_too_few_parts_returns_none(self):
        assert extract_control_id_from_rule_name("SC_AutoTrigger") is None

    def test_empty_string_returns_none(self):
        assert extract_control_id_from_rule_name("") is None


@mock_aws
class TestDiscoverEnabledV2Rules:
    """Tests for discover_enabled_v2_rules using moto EventBridge."""

    def _create_rule(self, name: str, state: str = "ENABLED") -> None:
        client = boto3.client("events", region_name="us-east-1")
        client.put_rule(
            Name=name,
            EventPattern='{"source": ["aws.securityhub"]}',
            State=state,
        )

    def test_finds_enabled_sc_rules(self):
        self._create_rule("SC_2.0.0_S3.5_AutoTrigger", "ENABLED")
        self._create_rule("SC_2.0.0_EC2.2_AutoTrigger", "DISABLED")
        self._create_rule("SC_2.0.0_CloudTrail.1_AutoTrigger", "ENABLED")

        result = discover_enabled_v2_rules()
        assert sorted(result) == ["CloudTrail.1", "S3.5"]

    def test_finds_rules_across_all_standards(self):
        self._create_rule("SC_2.0.0_S3.5_AutoTrigger", "ENABLED")
        self._create_rule("AFSBP_1.0.0_EC2.2_AutoTrigger", "ENABLED")
        self._create_rule("NIST80053R5_5.0.0_CloudTrail.1_AutoTrigger", "ENABLED")
        self._create_rule("PCI_3.2.1_PCI.IAM.7_AutoTrigger", "ENABLED")
        self._create_rule("CIS_1.2.0_1.20_AutoTrigger", "ENABLED")
        self._create_rule("CIS_1.4.0_2.1.2_AutoTrigger", "ENABLED")
        self._create_rule("CIS_3.0.0_2.3.2_AutoTrigger", "ENABLED")

        result = discover_enabled_v2_rules()
        assert sorted(result) == [
            "CloudTrail.1",
            "EC2.2",
            "IAM.18",  # CIS 1.2.0 1.20
            "IAM.7",  # PCI.IAM.7
            "RDS.13",  # CIS 3.0.0 2.3.2
            "S3.5",  # SC + CIS 1.4.0 2.1.2 (deduplicated)
        ]

    def test_deduplicates_overlapping_controls(self):
        # PCI.S3.5 and SC S3.5 both translate to S3.5 -> only one entry expected
        self._create_rule("SC_2.0.0_S3.5_AutoTrigger", "ENABLED")
        self._create_rule("PCI_3.2.1_PCI.S3.5_AutoTrigger", "ENABLED")

        result = discover_enabled_v2_rules()
        assert result == ["S3.5"]

    def test_skips_unmapped_cis_rules(self):
        # CIS v1.2.0 4.2 (port 3389) has no ASR remediation
        self._create_rule("CIS_1.2.0_4.2_AutoTrigger", "ENABLED")

        result = discover_enabled_v2_rules()
        assert result == []

    def test_returns_empty_when_no_rules(self):
        result = discover_enabled_v2_rules()
        assert result == []

    def test_returns_empty_when_all_disabled(self):
        self._create_rule("SC_2.0.0_S3.5_AutoTrigger", "DISABLED")
        self._create_rule("AFSBP_1.0.0_EC2.2_AutoTrigger", "DISABLED")
        self._create_rule("CIS_1.4.0_2.1.2_AutoTrigger", "DISABLED")

        result = discover_enabled_v2_rules()
        assert result == []

    def test_ignores_non_autotrigger_rules(self):
        self._create_rule("SC_2.0.0_S3.5_SomeOtherRule", "ENABLED")

        result = discover_enabled_v2_rules()
        assert result == []


@mock_aws
class TestWriteEnabledControlsToTable:
    """Tests for write_enabled_controls_to_table using moto DynamoDB."""

    TABLE_NAME = "test-remediation-config"

    def _create_table(self) -> None:
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName=self.TABLE_NAME,
            KeySchema=[{"AttributeName": "controlId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "controlId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

    def _seed_control(self, control_id: str) -> None:
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.Table(self.TABLE_NAME)
        table.put_item(
            Item={"controlId": control_id, "automatedRemediationEnabled": False}
        )

    def _get_control(self, control_id: str) -> dict[str, Any]:
        dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
        table = dynamodb.Table(self.TABLE_NAME)
        return cast(
            dict[str, Any],
            table.get_item(Key={"controlId": control_id}).get("Item", {}),
        )

    @patch.dict("os.environ", {"AWS_REGION": "us-east-1"})
    def test_updates_existing_controls(self):
        self._create_table()
        self._seed_control("S3.5")
        self._seed_control("EC2.2")

        result = write_enabled_controls_to_table(self.TABLE_NAME, ["S3.5", "EC2.2"])

        assert result["written"] == 2
        assert result["failed_controls"] == []
        assert self._get_control("S3.5")["automatedRemediationEnabled"] is True
        assert self._get_control("EC2.2")["automatedRemediationEnabled"] is True

    @patch.dict("os.environ", {"AWS_REGION": "us-east-1"})
    def test_returns_zero_for_empty_list(self):
        self._create_table()
        result = write_enabled_controls_to_table(self.TABLE_NAME, [])
        assert result["written"] == 0
        assert result["failed_controls"] == []

    @patch.dict("os.environ", {"AWS_REGION": "us-east-1"})
    def test_skips_nonexistent_controls(self):
        self._create_table()
        # NONEXISTENT.1 is not in the table — ConditionExpression fails
        result = write_enabled_controls_to_table(self.TABLE_NAME, ["NONEXISTENT.1"])
        assert result["written"] == 0
        # ConditionalCheckFailed is an expected skip, not a hard failure
        assert result["failed_controls"] == []

    @patch.dict("os.environ", {"AWS_REGION": "us-east-1"})
    def test_sets_modified_by_to_v2_migration(self):
        self._create_table()
        self._seed_control("S3.5")

        write_enabled_controls_to_table(self.TABLE_NAME, ["S3.5"])

        item = self._get_control("S3.5")
        assert item["modifiedBy"] == "v2-migration"

    @patch.dict("os.environ", {"AWS_REGION": "us-east-1"})
    def test_records_hard_failure_in_failed_controls(self):
        # Simulate a non-recoverable per-item ClientError (e.g. throttling) by
        # patching the table's update_item to raise. We cover the bookkeeping
        # path: write count stays 0 and the control is recorded as failed.
        self._create_table()
        self._seed_control("S3.5")

        from botocore.exceptions import ClientError

        class _UnrelatedException(Exception):
            """Stand-in so ConditionalCheckFailedException can never match."""

        with patch(
            "migration_auto_remediation_provider.boto3.resource"
        ) as mock_resource:
            mock_table = MagicMock()
            mock_table.update_item.side_effect = ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "Slow down"}},
                "UpdateItem",
            )
            mock_resource.return_value.Table.return_value = mock_table
            # Use a distinct exception so the broader ClientError branch runs
            # rather than being absorbed by ConditionalCheckFailed handling.
            mock_resource.return_value.meta.client.exceptions.ConditionalCheckFailedException = (
                _UnrelatedException
            )

            result = write_enabled_controls_to_table(self.TABLE_NAME, ["S3.5"])

        assert result["written"] == 0
        assert result["failed_controls"] == ["S3.5"]


@mock_aws
class TestNotifyMigrationFailure:
    """Tests for notify_migration_failure SNS publishing."""

    REGION = "us-east-1"

    def _create_topic(self) -> str:
        sns = boto3.client("sns", region_name=self.REGION)
        return cast(str, sns.create_topic(Name="test-asr-migration")["TopicArn"])

    def _list_subscriptions(self, topic_arn: str) -> list[dict[str, Any]]:
        sns = boto3.client("sns", region_name=self.REGION)
        return cast(
            list[dict[str, Any]],
            sns.list_subscriptions_by_topic(TopicArn=topic_arn).get(
                "Subscriptions", []
            ),
        )

    def test_returns_false_when_topic_not_configured(self):
        # No env var, no explicit arn -> notification skipped
        with patch.dict("os.environ", {}, clear=True):
            assert (
                notify_migration_failure(
                    failed_controls=["S3.5"], summary="something failed"
                )
                is False
            )

    @patch.dict("os.environ", {"AWS_REGION": REGION})
    def test_publishes_with_failed_controls_list(self):
        topic_arn = self._create_topic()

        # Capture the published message via a moto SQS subscription
        sqs = boto3.client("sqs", region_name=self.REGION)
        queue_url = sqs.create_queue(QueueName="capture")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        sns_client = boto3.client("sns", region_name=self.REGION)
        sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        published = notify_migration_failure(
            failed_controls=["S3.5", "EC2.2"],
            summary="ASR migrated 5 of 7 controls. 2 failed.",
            topic_arn=topic_arn,
        )

        assert published is True
        messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10).get(
            "Messages", []
        )
        assert len(messages) == 1
        body = messages[0]["Body"]
        # The wrapped SNS message contains both the summary and the per-control list
        assert "ASR migrated 5 of 7 controls" in body
        assert "S3.5" in body
        assert "EC2.2" in body

    @patch.dict("os.environ", {"AWS_REGION": REGION})
    def test_publishes_summary_only_when_no_failed_controls(self):
        topic_arn = self._create_topic()

        published = notify_migration_failure(
            failed_controls=[],
            summary="ASR migration aborted: EventBridge unavailable",
            topic_arn=topic_arn,
        )

        assert published is True

    @patch.dict("os.environ", {"AWS_REGION": REGION})
    def test_uses_env_var_when_topic_arn_not_passed(self):
        topic_arn = self._create_topic()

        with patch.dict("os.environ", {NOTIFICATION_TOPIC_ARN_ENV: topic_arn}):
            published = notify_migration_failure(
                failed_controls=["S3.5"], summary="failed"
            )

        assert published is True

    @patch.dict("os.environ", {"AWS_REGION": REGION})
    def test_returns_false_on_publish_error(self):
        # Non-existent topic ARN -> moto SNS returns NotFound
        bogus_arn = f"arn:aws:sns:{self.REGION}:123456789012:does-not-exist"

        published = notify_migration_failure(
            failed_controls=["S3.5"],
            summary="failed",
            topic_arn=bogus_arn,
        )

        assert published is False


class TestValidateEvent:
    """Tests for validate_event input validation."""

    def test_valid_create_event(self):
        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {"TableName": "my-table"},
        }
        result = validate_event(cast(CloudFormationCustomResourceEvent, event))
        assert result["request_type"] == "Create"
        assert result["table_name"] == "my-table"

    def test_valid_update_event(self):
        event: dict[str, Any] = {
            "RequestType": "Update",
            "ResourceProperties": {"TableName": "my-table"},
        }
        result = validate_event(cast(CloudFormationCustomResourceEvent, event))
        assert result["request_type"] == "Update"

    def test_valid_delete_event(self):
        event: dict[str, Any] = {
            "RequestType": "Delete",
            "ResourceProperties": {"TableName": "my-table"},
        }
        result = validate_event(cast(CloudFormationCustomResourceEvent, event))
        assert result["request_type"] == "Delete"

    def test_missing_table_name_raises(self):
        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {},
        }
        with pytest.raises(ValueError, match="TableName is required"):
            validate_event(cast(CloudFormationCustomResourceEvent, event))

    def test_empty_table_name_raises(self):
        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {"TableName": ""},
        }
        with pytest.raises(ValueError, match="TableName is required"):
            validate_event(cast(CloudFormationCustomResourceEvent, event))


class TestLambdaHandler:
    """Tests for the lambda_handler entry point."""

    @patch("migration_auto_remediation_provider.cfnresponse")
    @patch("migration_auto_remediation_provider.notify_migration_failure")
    @patch("migration_auto_remediation_provider.discover_enabled_v2_rules")
    @patch("migration_auto_remediation_provider.write_enabled_controls_to_table")
    def test_create_calls_migration(
        self, mock_write, mock_discover, mock_notify, mock_cfn
    ):
        mock_discover.return_value = ["S3.5", "EC2.2"]
        mock_write.return_value = {"written": 2, "failed_controls": []}

        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {
                "TableName": "test-table",
                "ServiceToken": "arn:...",
            },
        }
        lambda_handler(event, MagicMock())

        mock_discover.assert_called_once()
        mock_write.assert_called_once_with("test-table", ["S3.5", "EC2.2"])
        # Clean migration: no notification published
        mock_notify.assert_not_called()
        mock_cfn.send.assert_called_once()
        args = mock_cfn.send.call_args[0]
        assert args[2] == mock_cfn.SUCCESS

    @patch("migration_auto_remediation_provider.cfnresponse")
    @patch("migration_auto_remediation_provider.notify_migration_failure")
    @patch("migration_auto_remediation_provider.discover_enabled_v2_rules")
    @patch("migration_auto_remediation_provider.write_enabled_controls_to_table")
    def test_partial_failure_publishes_notification(
        self, mock_write, mock_discover, mock_notify, mock_cfn
    ):
        mock_discover.return_value = ["S3.5", "EC2.2", "RDS.13"]
        mock_write.return_value = {
            "written": 2,
            "failed_controls": ["RDS.13"],
        }

        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {
                "TableName": "test-table",
                "ServiceToken": "arn:...",
            },
        }
        lambda_handler(event, MagicMock())

        mock_notify.assert_called_once()
        kwargs = mock_notify.call_args.kwargs
        assert kwargs["failed_controls"] == ["RDS.13"]
        assert "2 of 3" in kwargs["summary"]

    @patch("migration_auto_remediation_provider.cfnresponse")
    @patch("migration_auto_remediation_provider.notify_migration_failure")
    @patch("migration_auto_remediation_provider.discover_enabled_v2_rules")
    def test_total_failure_publishes_notification(
        self, mock_discover, mock_notify, mock_cfn
    ):
        mock_discover.side_effect = RuntimeError("EventBridge unavailable")

        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {
                "TableName": "test-table",
                "ServiceToken": "arn:...",
            },
        }
        lambda_handler(event, MagicMock())

        mock_notify.assert_called_once()
        kwargs = mock_notify.call_args.kwargs
        assert kwargs["failed_controls"] == []
        assert "EventBridge unavailable" in kwargs["summary"]

    @patch("migration_auto_remediation_provider.cfnresponse")
    @patch("migration_auto_remediation_provider.discover_enabled_v2_rules")
    def test_update_is_noop(self, mock_discover, mock_cfn):
        event: dict[str, Any] = {
            "RequestType": "Update",
            "ResourceProperties": {
                "TableName": "test-table",
                "ServiceToken": "arn:...",
            },
        }
        lambda_handler(event, MagicMock())

        mock_discover.assert_not_called()
        mock_cfn.send.assert_called_once()

    @patch("migration_auto_remediation_provider.cfnresponse")
    @patch("migration_auto_remediation_provider.discover_enabled_v2_rules")
    def test_delete_is_noop(self, mock_discover, mock_cfn):
        event: dict[str, Any] = {
            "RequestType": "Delete",
            "ResourceProperties": {
                "TableName": "test-table",
                "ServiceToken": "arn:...",
            },
        }
        lambda_handler(event, MagicMock())

        mock_discover.assert_not_called()
        mock_cfn.send.assert_called_once()

    @patch("migration_auto_remediation_provider.cfnresponse")
    @patch("migration_auto_remediation_provider.discover_enabled_v2_rules")
    def test_exception_still_sends_success(self, mock_discover, mock_cfn):
        mock_discover.side_effect = RuntimeError("EventBridge unavailable")

        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {
                "TableName": "test-table",
                "ServiceToken": "arn:...",
            },
        }
        lambda_handler(event, MagicMock())

        mock_cfn.send.assert_called_once()
        args = mock_cfn.send.call_args[0]
        assert args[2] == mock_cfn.SUCCESS
        assert "Error" in args[3]
        assert "EventBridge unavailable" in args[3]["Error"]

    @patch("migration_auto_remediation_provider.cfnresponse")
    def test_missing_table_name_still_sends_success(self, mock_cfn):
        event: dict[str, Any] = {
            "RequestType": "Create",
            "ResourceProperties": {"ServiceToken": "arn:..."},
        }
        lambda_handler(event, MagicMock())

        mock_cfn.send.assert_called_once()
        args = mock_cfn.send.call_args[0]
        assert args[2] == mock_cfn.SUCCESS
        assert "Error" in args[3]
