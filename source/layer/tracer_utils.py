# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import Any, Dict, Optional

from aws_lambda_powertools import Tracer


class PowertoolsTracer:

    def __init__(self, service_name: Optional[str] = None):
        self.service_name = service_name or os.getenv("POWERTOOLS_SERVICE_NAME", "ASR")
        self.tracer = Tracer(service=self.service_name, auto_patch=True)

    def put_annotation(self, key: str, value: str) -> None:
        try:
            self.tracer.put_annotation(key, value)
        except Exception:
            pass

    def put_metadata(self, key: str, value: Any) -> None:
        try:
            self.tracer.put_metadata(key, value)
        except Exception:
            pass

    def add_finding_context(self, finding: Dict[str, Any]) -> None:
        try:
            if "Id" in finding:
                self.put_annotation("finding_id", finding["Id"])
            if "AwsAccountId" in finding:
                self.put_annotation("account_id", finding["AwsAccountId"])
            if "Region" in finding:
                self.put_annotation("region", finding["Region"])

            metadata = {
                k: v
                for k, v in finding.items()
                if k in ["Title", "GeneratorId", "ProductArn"]
            }
            if metadata:
                self.put_metadata("finding_context", metadata)
        except Exception:
            pass

    def add_remediation_context(self, remediation: Dict[str, Any]) -> None:
        try:
            if "security_standard" in remediation:
                self.put_annotation(
                    "security_standard", remediation["security_standard"]
                )
            if "control_id" in remediation:
                self.put_annotation("control_id", remediation["control_id"])
            if "automation_doc_id" in remediation:
                self.put_annotation("automation_doc", remediation["automation_doc_id"])

            self.put_metadata("remediation_context", remediation)
        except Exception:
            pass

    def capture_lambda_handler(self, lambda_handler):
        return self.tracer.capture_lambda_handler(lambda_handler)

    @property
    def trace(self) -> Tracer:
        return self.tracer


def init_tracer(service_name: Optional[str] = None) -> PowertoolsTracer:
    return PowertoolsTracer(service_name)


def get_tracer() -> PowertoolsTracer:
    return init_tracer()


def add_trace_annotation(tracer_instance: PowertoolsTracer, **annotations: Any) -> None:
    for key, value in annotations.items():
        tracer_instance.put_annotation(key, str(value))


def add_trace_metadata(tracer_instance: PowertoolsTracer, **metadata: Any) -> None:
    for key, value in metadata.items():
        tracer_instance.put_metadata(key, value)


def add_finding_context(
    tracer_instance: PowertoolsTracer, finding: Dict[str, Any]
) -> None:
    tracer_instance.add_finding_context(finding)


def add_remediation_context(
    tracer_instance: PowertoolsTracer, remediation: Dict[str, Any]
) -> None:
    tracer_instance.add_remediation_context(remediation)


tracer = init_tracer()
