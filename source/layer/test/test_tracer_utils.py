# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from unittest.mock import Mock, patch

import pytest
from layer.tracer_utils import (
    PowertoolsTracer,
    add_finding_context,
    add_remediation_context,
    add_trace_annotation,
    add_trace_metadata,
    get_tracer,
    init_tracer,
)


class TestTracerInitialization:
    @patch.dict(os.environ, {"POWERTOOLS_SERVICE_NAME": "TEST_SERVICE"})
    def test_init_tracer_with_service_name(self):
        tracer_instance = init_tracer()
        assert tracer_instance is not None
        assert tracer_instance.service_name == "TEST_SERVICE"

    @patch.dict(os.environ, {}, clear=True)
    def test_init_tracer_default_service_name(self):
        tracer_instance = init_tracer()
        assert tracer_instance is not None
        assert tracer_instance.service_name == "ASR"

    def test_init_tracer_with_explicit_service_name(self):
        tracer_instance = init_tracer("EXPLICIT_SERVICE")
        assert tracer_instance is not None
        assert tracer_instance.service_name == "EXPLICIT_SERVICE"

    def test_get_tracer_returns_instance(self):
        tracer_instance = get_tracer()
        assert tracer_instance is not None
        assert isinstance(tracer_instance, PowertoolsTracer)


class TestPowertoolsTracerClass:

    def test_tracer_class_initialization(self):
        tracer_instance = PowertoolsTracer("test_service")
        assert tracer_instance.service_name == "test_service"
        assert tracer_instance.tracer is not None

    def test_put_annotation_success(self):
        tracer_instance = PowertoolsTracer("test_service")
        tracer_instance.put_annotation("test_key", "test_value")
        tracer_instance.put_annotation("count", "42")

    def test_put_metadata_success(self):
        tracer_instance = PowertoolsTracer("test_service")
        tracer_instance.put_metadata("test_key", {"nested": "value"})
        tracer_instance.put_metadata("simple", "value")

    def test_capture_lambda_handler_decorator(self):
        tracer_instance = PowertoolsTracer("test_service")

        @tracer_instance.capture_lambda_handler
        def test_handler(event, context):
            return {"statusCode": 200, "body": "success"}

        result = test_handler({}, Mock())
        assert result["statusCode"] == 200

    def test_trace_property_access(self):
        tracer_instance = PowertoolsTracer("test_service")
        from aws_lambda_powertools import Tracer

        assert isinstance(tracer_instance.trace, Tracer)


class TestStandaloneFunctions:

    def test_add_trace_metadata_with_mock_tracer(self):
        mock_tracer = Mock()
        test_metadata = {"key1": "value1", "key2": "value2", "key3": 123}

        add_trace_metadata(mock_tracer, **test_metadata)

        assert mock_tracer.put_metadata.call_count == 3
        mock_tracer.put_metadata.assert_any_call("key1", "value1")
        mock_tracer.put_metadata.assert_any_call("key2", "value2")
        mock_tracer.put_metadata.assert_any_call("key3", 123)

    def test_add_trace_annotation_with_mock_tracer(self):
        mock_tracer = Mock()
        test_annotations = {"status": "SUCCESS", "control_id": "S3.1", "count": 42}

        add_trace_annotation(mock_tracer, **test_annotations)

        assert mock_tracer.put_annotation.call_count == 3
        mock_tracer.put_annotation.assert_any_call("status", "SUCCESS")
        mock_tracer.put_annotation.assert_any_call("control_id", "S3.1")
        mock_tracer.put_annotation.assert_any_call("count", "42")

    def test_add_trace_metadata_with_real_tracer(self):
        tracer_instance = init_tracer("test_service")
        add_trace_metadata(tracer_instance, test_key="test_value", count=42)

    def test_add_trace_annotation_with_real_tracer(self):
        tracer_instance = init_tracer("test_service")
        add_trace_annotation(tracer_instance, status="SUCCESS", control_id="S3.1")


class TestFindingContextTracing:

    def test_add_finding_context_complete_with_mock(self):
        mock_tracer = Mock()
        finding = {
            "Id": "test-finding-id",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Test Security Finding",
            "GeneratorId": "test-generator",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        }

        add_finding_context(mock_tracer, finding)

        mock_tracer.add_finding_context.assert_called_once_with(finding)

    def test_add_finding_context_with_real_tracer(self):
        tracer_instance = init_tracer("test_service")
        finding = {
            "Id": "test-finding-id",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Test Security Finding",
            "GeneratorId": "test-generator",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        }

        add_finding_context(tracer_instance, finding)

    def test_tracer_class_add_finding_context_complete(self):
        tracer_instance = PowertoolsTracer("test_service")
        finding = {
            "Id": "test-finding-id",
            "AwsAccountId": "123456789012",
            "Region": "us-east-1",
            "Title": "Test Security Finding",
            "GeneratorId": "test-generator",
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
        }

        tracer_instance.add_finding_context(finding)

    def test_tracer_class_add_finding_context_partial(self):
        tracer_instance = PowertoolsTracer("test_service")
        finding = {"Id": "test-finding-id", "AwsAccountId": "123456789012"}

        tracer_instance.add_finding_context(finding)

    def test_tracer_class_add_finding_context_empty(self):
        tracer_instance = PowertoolsTracer("test_service")

        tracer_instance.add_finding_context({})


class TestRemediationContextTracing:

    def test_add_remediation_context_complete_with_mock(self):
        mock_tracer = Mock()
        remediation_data = {
            "security_standard": "AFSBP",
            "control_id": "S3.1",
            "automation_doc_id": "ASR-AFSBP_1.0.0_S3.1",
        }

        add_remediation_context(mock_tracer, remediation_data)

        mock_tracer.add_remediation_context.assert_called_once_with(remediation_data)

    def test_add_remediation_context_with_real_tracer(self):
        tracer_instance = init_tracer("test_service")
        remediation_data = {
            "security_standard": "AFSBP",
            "control_id": "S3.1",
            "automation_doc_id": "ASR-AFSBP_1.0.0_S3.1",
        }

        add_remediation_context(tracer_instance, remediation_data)

    def test_tracer_class_add_remediation_context_complete(self):
        tracer_instance = PowertoolsTracer("test_service")
        remediation_data = {
            "security_standard": "AFSBP",
            "control_id": "S3.1",
            "automation_doc_id": "ASR-AFSBP_1.0.0_S3.1",
            "account_id": "123456789012",
            "region": "us-east-1",
        }

        tracer_instance.add_remediation_context(remediation_data)

    def test_tracer_class_add_remediation_context_partial(self):
        tracer_instance = PowertoolsTracer("test_service")
        remediation_data = {"control_id": "S3.1"}

        tracer_instance.add_remediation_context(remediation_data)

    def test_tracer_class_add_remediation_context_empty(self):
        tracer_instance = PowertoolsTracer("test_service")

        tracer_instance.add_remediation_context({})


class TestBackwardCompatibility:

    def test_global_tracer_variable_exists(self):
        from layer.tracer_utils import tracer

        assert tracer is not None
        assert isinstance(tracer, PowertoolsTracer)

    def test_tracer_has_expected_methods(self):
        tracer_instance = init_tracer()
        assert hasattr(tracer_instance, "capture_lambda_handler")
        assert hasattr(tracer_instance, "put_annotation")
        assert hasattr(tracer_instance, "put_metadata")
        assert hasattr(tracer_instance, "add_finding_context")
        assert hasattr(tracer_instance, "add_remediation_context")
        assert hasattr(tracer_instance, "trace")

    def test_all_expected_functions_importable(self):
        from layer.tracer_utils import (
            PowertoolsTracer,
            add_finding_context,
            add_remediation_context,
            add_trace_annotation,
            add_trace_metadata,
            get_tracer,
            init_tracer,
        )

        assert PowertoolsTracer is not None
        assert add_finding_context is not None
        assert add_remediation_context is not None
        assert add_trace_annotation is not None
        assert add_trace_metadata is not None
        assert get_tracer is not None
        assert init_tracer is not None


class TestErrorHandling:

    def test_tracer_class_methods_handle_errors_gracefully(self):
        tracer_instance = PowertoolsTracer("test_service")

        try:
            tracer_instance.put_annotation("", "")
            tracer_instance.put_metadata("test", None)
            tracer_instance.add_finding_context({"invalid": "data"})
            tracer_instance.add_remediation_context({"missing": "fields"})
            assert tracer_instance is not None
            assert hasattr(tracer_instance, "put_annotation")
            assert hasattr(tracer_instance, "put_metadata")
            assert hasattr(tracer_instance, "add_finding_context")
            assert hasattr(tracer_instance, "add_remediation_context")
        except Exception as e:
            pytest.fail(f"Tracer methods should handle errors gracefully: {e}")

    def test_standalone_functions_handle_errors_gracefully(self):
        tracer_instance = init_tracer("test_service")

        try:
            add_trace_annotation(tracer_instance, empty_key="")
            add_trace_metadata(tracer_instance, none_value=None)
            add_finding_context(tracer_instance, {})
            add_remediation_context(tracer_instance, {})
            assert tracer_instance is not None
            assert callable(add_trace_annotation)
            assert callable(add_trace_metadata)
            assert callable(add_finding_context)
            assert callable(add_remediation_context)
        except Exception as e:
            pytest.fail(f"Standalone functions should handle errors gracefully: {e}")
