# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from unittest.mock import MagicMock, patch

import pytest
from layer.powertools_logger import PowertoolsLogger, get_logger
from layer.tracer_utils import PowertoolsTracer, get_tracer, init_tracer, tracer


class TestSimplePowertoolsLogger:

    def test_logger_initialization(self):
        logger = PowertoolsLogger("test_service", "info")
        assert logger.service_name == "test_service"
        assert isinstance(logger.level, int)

        logger2 = get_logger("test_service", "debug")
        assert logger2.service_name == "test_service"

    def test_all_logging_methods(self):
        logger = get_logger("test_service", "debug")

        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")
        logger.exception("Exception message")

        logger.debug("Debug message", key1="value1")
        logger.info("Info message", key2="value2")
        logger.warning("Warning message", key3="value3")
        logger.error("Error message", key4="value4")
        logger.critical("Critical message", key5="value5")
        logger.exception("Exception message", key6="value6")

        assert logger is not None
        assert hasattr(logger, "debug")
        assert hasattr(logger, "info")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")
        assert hasattr(logger, "critical")
        assert hasattr(logger, "exception")

    def test_logger_configuration_methods(self):
        logger = get_logger("test_service", "info")

        logger.add_persistent_keys(service_version="1.0.0", env="test")
        logger.remove_keys(["service_version"])
        logger.config("warning")
        logger.set_correlation_id("test-correlation-123")

        assert logger is not None
        assert hasattr(logger, "add_persistent_keys")
        assert hasattr(logger, "remove_keys")
        assert hasattr(logger, "config")
        assert hasattr(logger, "set_correlation_id")

    def test_lambda_context_injection(self):
        logger = get_logger("test_service", "info")

        mock_context = MagicMock()
        mock_context.function_name = "test-function"
        mock_context.function_version = "$LATEST"
        mock_context.aws_request_id = "test-request-id"

        logger.inject_lambda_context(mock_context, log_event=True)

        assert logger is not None
        assert hasattr(logger, "inject_lambda_context")

    def test_logger_properties(self):
        logger = get_logger("test_service", "info")

        level = logger.level
        assert isinstance(level, int)

        from aws_lambda_powertools import Logger

        assert isinstance(logger.log, Logger)

    @patch.dict(os.environ, {"POWERTOOLS_SERVICE_NAME": "ASR"})
    def test_environment_variable_usage(self):
        logger = PowertoolsLogger()
        assert logger.service_name == "ASR"


class TestSimplePowertoolsTracer:

    def test_tracer_initialization(self):
        tracer_instance = PowertoolsTracer("test_service")
        assert tracer_instance.service_name == "test_service"

        tracer2 = init_tracer("test_service")
        assert tracer2.service_name == "test_service"

        tracer3 = get_tracer()
        assert tracer3 is not None

    def test_tracer_annotations_and_metadata(self):
        tracer_instance = init_tracer("test_service")

        tracer_instance.put_annotation("test_key", "test_value")
        tracer_instance.put_annotation("count", "42")

        tracer_instance.put_metadata("test_metadata", {"key": "value", "count": 123})
        tracer_instance.put_metadata("simple_value", "test")

        assert tracer_instance is not None
        assert hasattr(tracer_instance, "put_annotation")
        assert hasattr(tracer_instance, "put_metadata")

    def test_finding_context(self):
        tracer_instance = init_tracer("test_service")

        complete_finding = {
            "Id": "test-finding-id-123",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Test Security Finding",
            "GeneratorId": "test-generator-id",
            "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/test",
        }

        tracer_instance.add_finding_context(complete_finding)

        minimal_finding = {"Id": "minimal-finding-id"}

        tracer_instance.add_finding_context(minimal_finding)

        tracer_instance.add_finding_context({})

        assert tracer_instance is not None
        assert hasattr(tracer_instance, "add_finding_context")

    def test_remediation_context(self):
        tracer_instance = init_tracer("test_service")

        complete_remediation = {
            "security_standard": "AWS-FSBP",
            "control_id": "EC2.1",
            "automation_doc_id": "ASR-AWS-FSBP_1.0.0_EC2.1",
            "account_id": "123456789012",
            "region": "us-east-1",
        }

        tracer_instance.add_remediation_context(complete_remediation)

        minimal_remediation = {"control_id": "S3.1"}

        tracer_instance.add_remediation_context(minimal_remediation)

        tracer_instance.add_remediation_context({})

        assert tracer_instance is not None
        assert hasattr(tracer_instance, "add_remediation_context")

    def test_tracer_property(self):
        tracer_instance = init_tracer("test_service")

        from aws_lambda_powertools import Tracer

        assert isinstance(tracer_instance.trace, Tracer)

    @patch.dict(os.environ, {"POWERTOOLS_SERVICE_NAME": "ASR"})
    def test_environment_variable_usage(self):
        tracer_instance = PowertoolsTracer()
        assert tracer_instance.service_name == "ASR"

    def test_global_tracer_instance(self):
        assert tracer is not None
        tracer.put_annotation("global_test", "value")
        tracer.put_metadata("global_metadata", {"test": True})

    def test_capture_lambda_handler_decorator(self):
        tracer_instance = init_tracer("test_service")

        @tracer_instance.capture_lambda_handler
        def test_lambda_handler(event, context):
            return {"statusCode": 200, "body": "success"}

        assert hasattr(tracer_instance, "capture_lambda_handler")
        assert callable(tracer_instance.capture_lambda_handler)


class TestIntegration:

    def test_logger_and_tracer_together(self):

        logger = get_logger("integration_test", "info")
        tracer_instance = init_tracer("integration_test")

        finding = {
            "Id": "integration-finding-123",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Integration Test Finding",
        }

        remediation = {
            "security_standard": "AWS-FSBP",
            "control_id": "EC2.1",
            "automation_doc_id": "ASR-AWS-FSBP_1.0.0_EC2.1",
        }

        tracer_instance.add_finding_context(finding)
        tracer_instance.add_remediation_context(remediation)

        logger.info("Starting remediation", finding_id=finding["Id"])
        logger.info("Processing control", control_id=remediation["control_id"])
        logger.info("Remediation completed", status="SUCCESS")

        assert logger is not None
        assert tracer_instance is not None
        assert logger.service_name == "integration_test"
        assert tracer_instance.service_name == "integration_test"

    def test_error_handling_robustness(self):
        logger = get_logger("error_test", "info")
        tracer_instance = init_tracer("error_test")

        try:
            logger.info(
                "Test message",
                complex_data={"nested": {"deep": {"list": [1, 2, 3]}}},
                none_value=None,
                empty_dict={},
                empty_list=[],
            )

            tracer_instance.put_annotation("test", "")
            tracer_instance.put_metadata("test", None)
            tracer_instance.add_finding_context({"invalid": "data"})
            tracer_instance.add_remediation_context({"missing": "fields"})

        except Exception as e:
            pytest.fail(f"Error handling should be robust: {e}")

    def test_api_compatibility(self):
        logger = get_logger("compat_test", "info")
        tracer_instance = init_tracer("compat_test")

        logger.add_persistent_keys(service_name="ASR", version="1.0.0")
        logger.set_correlation_id("test-correlation-456")

        tracer_instance.put_annotation("service", "ASR")
        tracer_instance.put_annotation("version", "1.0.0")

        logger.info(
            "Processing request",
            request_id="req-123",
            user_id="user-456",
            action="remediate",
        )

        tracer_instance.put_annotation("request_id", "req-123")
        tracer_instance.put_annotation("action", "remediate")

        assert logger is not None
        assert tracer_instance is not None
        assert logger.service_name == "compat_test"
        assert tracer_instance.service_name == "compat_test"
