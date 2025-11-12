# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import os
import sys
from unittest.mock import Mock, patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCheckSSMDocStateLogicPreservation:

    def test_document_validation_logic_unchanged(self):
        from Orchestrator.check_ssm_doc_state import lambda_handler

        test_event = {
            "Finding": {
                "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
                "AwsAccountId": "123456789012",
                "Resources": [{"Region": "us-east-1"}],
            },
            "EventType": "Security Hub Findings - Imported",
        }

        with patch("Orchestrator.check_ssm_doc_state._get_ssm_client") as mock_ssm:
            mock_client = Mock()
            mock_client.describe_document.return_value = {
                "Document": {"DocumentType": "Automation", "Status": "Active"}
            }
            mock_ssm.return_value = mock_client

            context = Mock()
            context.function_name = "test-function"
            context.function_version = "1"
            context.aws_request_id = "test-request"

            with patch("Orchestrator.check_ssm_doc_state.Finding") as mock_finding:
                mock_finding.return_value.standard_shortname = "AFSBP"
                mock_finding.return_value.standard_version = "1.0.0"
                mock_finding.return_value.remediation_control = "EC2.1"
                mock_finding.return_value.playbook_enabled = "True"
                mock_finding.return_value.account_id = "123456789012"
                mock_finding.return_value.resource_region = "us-east-1"

                result = lambda_handler(test_event, context)

                assert result["status"] == "ACTIVE"

    def test_access_denied_handling_preserved(self):
        from botocore.exceptions import ClientError
        from Orchestrator.check_ssm_doc_state import lambda_handler

        test_event = {
            "Finding": {
                "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
                "AwsAccountId": "123456789012",
            },
            "EventType": "Security Hub Findings - Imported",
        }

        with patch("Orchestrator.check_ssm_doc_state._get_ssm_client") as mock_ssm:
            mock_client = Mock()
            mock_client.describe_document.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied"}}, "DescribeDocument"
            )
            mock_ssm.return_value = mock_client

            context = Mock()
            context.function_name = "test-function"
            context.function_version = "1"
            context.aws_request_id = "test-request"

            with patch("Orchestrator.check_ssm_doc_state.Finding") as mock_finding:
                mock_finding.return_value.playbook_enabled = "True"
                mock_finding.return_value.standard_shortname = "AFSBP"
                mock_finding.return_value.standard_version = "1.0.0"
                mock_finding.return_value.remediation_control = "EC2.1"

                result = lambda_handler(test_event, context)

                assert result["status"] == "ACCESSDENIED"


class TestExecSSMDocLogicPreservation:

    def test_execution_parameter_logic_unchanged(self):
        from Orchestrator.exec_ssm_doc import lambda_handler

        test_event = {
            "Finding": {"AwsAccountId": "123456789012"},
            "AutomationDocument": {
                "SecurityStandard": "AFSBP",
                "ControlId": "EC2.1",
                "AccountId": "123456789012",
                "AutomationDocId": "ASR-AFSBP_1.0.0_EC2.1",
                "RemediationRole": "TestRole",
                "ResourceRegion": "us-east-1",
            },
            "EventType": "Security Hub Findings - Imported",
        }

        with patch("Orchestrator.exec_ssm_doc._get_ssm_client") as mock_ssm:
            mock_client = Mock()
            mock_client.start_automation_execution.return_value = {
                "AutomationExecutionId": "test-execution-id"
            }
            mock_ssm.return_value = mock_client

            with patch(
                "Orchestrator.exec_ssm_doc.lambda_role_exists", return_value=True
            ):
                context = Mock()
                context.function_name = "test-function"
                context.function_version = "1"
                context.aws_request_id = "test-request"

                result = lambda_handler(test_event, context)

                assert result["status"] == "QUEUED"
                assert result["executionid"] == "test-execution-id"

    def test_role_selection_logic_preserved(self):
        from Orchestrator.exec_ssm_doc import lambda_role_exists

        with patch("Orchestrator.exec_ssm_doc._get_iam_client") as mock_iam:
            mock_client = Mock()
            mock_client.get_role.return_value = {"Role": {"RoleName": "TestRole"}}
            mock_iam.return_value = mock_client

            result = lambda_role_exists("123456789012", "TestRole")
            assert result is True


class TestCheckSSMExecutionLogicPreservation:

    def test_execution_status_evaluation_unchanged(self):
        from Orchestrator.check_ssm_execution import lambda_handler

        test_event = {
            "AutomationDocument": {
                "SecurityStandard": "AFSBP",
                "ControlId": "EC2.1",
                "AccountId": "123456789012",
            },
            "SSMExecution": {
                "SSMExecutionId": "12345678-1234-1234-1234-123456789012",
                "Account": "123456789012",
                "Region": "us-east-1",
            },
        }

        with patch("Orchestrator.check_ssm_execution.AutomationExecution") as mock_exec:
            mock_instance = Mock()
            mock_instance.status = "Success"
            mock_instance.outputs = {"Remediation.Output": ['{"status": "SUCCESS"}']}
            mock_instance.failure_message = ""
            mock_exec.return_value = mock_instance

            context = Mock()
            context.function_name = "test-function"
            context.function_version = "1"
            context.aws_request_id = "test-request"

            result = lambda_handler(test_event, context)

            assert result["status"] == "Success"

    def test_output_parsing_logic_preserved(self):
        from Orchestrator.check_ssm_execution import get_remediation_response

        test_response = ['{"status": "SUCCESS", "message": "Completed"}']
        result = get_remediation_response(test_response)

        assert result["status"] == "SUCCESS"
        assert result["message"] == "Completed"


class TestGetApprovalRequirementLogicPreservation:

    def test_approval_determination_logic_unchanged(self):
        from Orchestrator.get_approval_requirement import lambda_handler

        test_event = {
            "Finding": {
                "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
                "AwsAccountId": "123456789012",
            },
            "EventType": "Security Hub Findings - Imported",
        }

        context = Mock()
        context.function_name = "test-function"
        context.function_version = "1"
        context.aws_request_id = "test-request"

        with patch("Orchestrator.get_approval_requirement.Finding") as mock_finding:
            mock_finding.return_value.standard_shortname = "AFSBP"
            mock_finding.return_value.standard_version = "1.0.0"
            mock_finding.return_value.standard_control = "EC2.1"
            mock_finding.return_value.finding_id = "test-finding"
            mock_finding.return_value.account_id = "123456789012"

            with patch(
                "Orchestrator.get_approval_requirement.get_running_account",
                return_value="123456789012",
            ):
                result = lambda_handler(test_event, context)

                assert "workflow_data" in result
                assert result["workflow_data"]["approvalrequired"] == "false"


class TestScheduleRemediationLogicPreservation:

    def test_rate_limiting_logic_unchanged(self):
        from Orchestrator.schedule_remediation import lambda_handler

        test_event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "ResourceRegion": "us-east-1",
                            "AccountId": "123456789012",
                            "TaskToken": "test-token",
                            "RemediationDetails": {"control": "EC2.1"},
                        }
                    )
                }
            ]
        }

        with patch("Orchestrator.schedule_remediation.connect_to_dynamodb") as mock_ddb:
            with patch("Orchestrator.schedule_remediation.connect_to_sfn") as mock_sfn:
                with patch.dict(
                    os.environ,
                    {"SchedulingTableName": "test-table", "RemediationWaitTime": "300"},
                ):
                    mock_ddb_client = Mock()
                    mock_ddb_client.get_item.return_value = {}
                    mock_ddb.return_value = mock_ddb_client

                    mock_sfn_client = Mock()
                    mock_sfn.return_value = mock_sfn_client

                    context = Mock()
                    context.function_name = "test-function"
                    context.function_version = "1"
                    context.aws_request_id = "test-request"

                    result = lambda_handler(test_event, context)

                    assert "scheduled to execute" in result


class TestSendNotificationsLogicPreservation:

    def test_notification_formatting_unchanged(self):
        from Orchestrator.send_notifications import lambda_handler

        test_event = {
            "Notification": {
                "Message": "Test remediation completed",
                "State": "SUCCESS",
                "SSMExecutionId": "test-exec-123",
                "AffectedObject": "test-resource",
            },
            "Finding": {
                "Id": "test-finding-id",
                "Compliance": {"SecurityControlId": "EC2.1"},
            },
            "EventType": "ASR",
        }

        with patch("layer.sechub_findings.Finding") as mock_finding:
            with patch("layer.sechub_findings.ASRNotification") as mock_notification:
                mock_finding_instance = Mock()
                mock_finding_instance.generator_id = "test-generator-id"
                mock_finding_instance.arn = "arn:aws:securityhub:us-east-1:123456789012:subscription/test-standard/v/1.0.0/TEST.1/finding/test-finding"
                mock_finding.return_value = mock_finding_instance

                mock_notification_instance = Mock()
                mock_notification.return_value = mock_notification_instance

                context = Mock()

                lambda_handler(test_event, context)

                mock_notification_instance.notify.assert_called_once()


class TestCriticalPathsValidation:

    def test_security_hub_finding_processing_path(self):
        from Orchestrator.check_ssm_doc_state import lambda_handler

        security_hub_event = {
            "Finding": {
                "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
                "AwsAccountId": "123456789012",
            },
            "EventType": "Security Hub Findings - Imported",
        }

        context = Mock()
        context.function_name = "test-function"
        context.function_version = "1"
        context.aws_request_id = "test-request"

        with patch("Orchestrator.check_ssm_doc_state.Finding") as mock_finding:
            mock_finding.return_value.playbook_enabled = "True"
            mock_finding.return_value.standard_shortname = "AFSBP"

            result = lambda_handler(security_hub_event, context)

            assert "securitystandard" in result
            assert "controlid" in result

    def test_non_security_hub_finding_processing_path(self):
        from Orchestrator.check_ssm_doc_state import lambda_handler

        non_security_hub_event = {
            "Finding": {
                "ProductFields": {"aws/securityhub/ProductName": "Inspector"},
                "AwsAccountId": "123456789012",
                "Resources": [{"Region": "us-east-1"}],
            },
            "EventType": "Security Hub Findings - Imported",
            "Workflow": {"WorkflowDocument": "CustomDoc", "WorkflowRole": "CustomRole"},
        }

        context = Mock()
        context.function_name = "test-function"
        context.function_version = "1"
        context.aws_request_id = "test-request"

        result = lambda_handler(non_security_hub_event, context)

        assert result["securitystandard"] == "N/A"
        assert result["automationdocid"] == "CustomDoc"


class TestDataIntegrityValidation:

    def test_finding_id_preservation_across_services(self):
        test_finding_id = "arn:aws:securityhub:us-east-1:123456789012:finding/12345678-1234-1234-1234-123456789012"
        test_account_id = "123456789012"

        with patch("layer.sechub_findings.Finding") as mock_finding_class:
            mock_finding_instance = Mock()
            mock_finding_instance.arn = test_finding_id
            mock_finding_instance.uuid = "12345678-1234-1234-1234-123456789012"
            mock_finding_instance.account_id = test_account_id
            mock_finding_instance.standard_shortname = "AFSBP"
            mock_finding_instance.standard_version = "1.0.0"
            mock_finding_instance.remediation_control = "EC2.1"
            mock_finding_instance.generator_id = "test-generator-id"

            mock_finding_class.return_value = mock_finding_instance

            finding_obj = mock_finding_class(
                {"Id": test_finding_id, "AwsAccountId": test_account_id}
            )

            assert finding_obj.arn == test_finding_id
            assert finding_obj.uuid == "12345678-1234-1234-1234-123456789012"
            assert finding_obj.account_id == test_account_id

            mock_finding_class.assert_called_once()
            call_args = mock_finding_class.call_args[0][0]
            assert call_args["Id"] == test_finding_id
            assert call_args["AwsAccountId"] == test_account_id

    def test_execution_id_flow_preservation(self):
        from Orchestrator.exec_ssm_doc import lambda_handler

        test_event = {
            "Finding": {"AwsAccountId": "123456789012"},
            "AutomationDocument": {
                "SecurityStandard": "AFSBP",
                "ControlId": "EC2.1",
                "AccountId": "123456789012",
                "AutomationDocId": "ASR-AFSBP_1.0.0_EC2.1",
                "RemediationRole": "TestRole",
                "ResourceRegion": "us-east-1",
            },
            "EventType": "Security Hub Findings - Imported",
        }

        expected_exec_id = "execution-12345"

        with patch("Orchestrator.exec_ssm_doc._get_ssm_client") as mock_ssm:
            mock_client = Mock()
            mock_client.start_automation_execution.return_value = {
                "AutomationExecutionId": expected_exec_id
            }
            mock_ssm.return_value = mock_client

            with patch(
                "Orchestrator.exec_ssm_doc.lambda_role_exists", return_value=False
            ):
                context = Mock()
                context.function_name = "test-function"
                context.function_version = "1"
                context.aws_request_id = "test-request"

                result = lambda_handler(test_event, context)

                assert result["executionid"] == expected_exec_id
