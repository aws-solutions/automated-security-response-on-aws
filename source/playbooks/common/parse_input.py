# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# NOTE: Comments are kept minimal to reduce CloudFormation template size.
# This script is embedded inline in every control runbook SSM document.
import json
import re
from typing import Any

import boto3
from botocore.config import Config


def connect_to_config(boto_config):
    return boto3.client("config", config=boto_config)


def connect_to_ssm(boto_config):
    return boto3.client("ssm", config=boto_config)


def get_solution_id():
    return "SO0111"


def get_solution_version():
    ssm = connect_to_ssm(
        Config(
            retries={"mode": "standard"},
            user_agent_extra=f"AwsSolution/{get_solution_id()}/unknown",
        )
    )
    solution_version = "unknown"
    try:
        ssm_parm_value = ssm.get_parameter(
            Name=f"/Solutions/{get_solution_id()}/member-version"
        )["Parameter"].get("Value", "unknown")
        solution_version = ssm_parm_value
    except Exception as e:
        print(e)
        print("ERROR getting solution version")
    return solution_version


def get_shortname(long_name):
    short_name = {
        "aws-foundational-security-best-practices": "AFSBP",
        "cis-aws-foundations-benchmark": "CIS",
        "pci-dss": "PCI",
        "security-control": "SC",
    }
    return short_name.get(long_name, None)


def get_config_rule(rule_name):
    boto_config = Config(
        retries={"mode": "standard"},
        user_agent_extra=f"AwsSolution/{get_solution_id()}/{get_solution_version()}",
    )
    config_rule = None
    try:
        configsvc = connect_to_config(boto_config)
        config_rule = configsvc.describe_config_rules(ConfigRuleNames=[rule_name]).get(
            "ConfigRules", []
        )[0]
    except Exception as e:
        print(e)
        exit(f"ERROR getting config rule {rule_name}")
    return config_rule


class FindingEvent:

    product_arn: str | None

    def _get_resource_id(self, parse_id_pattern, resource_index):
        identifier_raw = self.finding_json["Resources"][0]["Id"]
        self.resource_id = identifier_raw
        self.resource_id_matches = []

        if parse_id_pattern:
            identifier_match = re.match(parse_id_pattern, identifier_raw)

            if identifier_match:
                for group in range(1, len(identifier_match.groups()) + 1):
                    self.resource_id_matches.append(identifier_match.group(group))
                self.resource_id = identifier_match.group(resource_index)
            else:
                exit(f"ERROR: Invalid resource Id {identifier_raw}")

    def _get_sc_check(self):
        match_finding_id = re.match(
            r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:"
            + "security-control/(.*)/finding/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$",
            self.finding_json["Id"],
        )
        if match_finding_id:
            self.standard_id = get_shortname("security-control")
            self.control_id = match_finding_id.group(1)

        return match_finding_id

    def _get_standard_info(self):
        match_finding_id = re.match(
            r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:"
            + r"subscription/(.*?)/v/(\d+\.\d+\.\d+)/(.*)/finding/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})$",
            self.finding_json["Id"],
        )
        if match_finding_id:
            self.standard_id = get_shortname(match_finding_id.group(1))
            self.standard_version = match_finding_id.group(2)
            self.control_id = match_finding_id.group(3)
        else:
            match_sc_finding_id = self._get_sc_check()
            if not match_sc_finding_id:
                self.valid_finding = False
                self.invalid_finding_reason = (
                    f'Finding Id is invalid: {self.finding_json["Id"]}'
                )

    def _fetch_aws_config_rule(self) -> tuple[str | None, dict[str, Any]]:
        product_fields = self.finding_json.get("ProductFields", {})
        if (
            product_fields.get("RelatedAWSResources:0/type")
            != "AWS::Config::ConfigRule"
        ):
            return None, {}
        rule_name = product_fields.get("RelatedAWSResources:0/name")
        if not rule_name:
            return None, {}
        return rule_name, get_config_rule(rule_name)

    def _get_region_from_resource_id(self):
        check_for_region = re.match(
            r"^arn:(?:aws|aws-cn|aws-us-gov):[a-zA-Z0-9]+:([a-z]{2}(?:-gov)?-[a-z]+-\d):.*:.*$",
            self.finding_json["Resources"][0]["Id"],
        )
        if check_for_region:
            self.resource_region = check_for_region.group(1)
        else:
            self.resource_region = self.finding_json["Resources"][0]["Region"]

    def _resolve_product_arn(self) -> None:
        if not self.valid_finding:
            return
        pa_pattern = r"^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d::(?:product|productv2)/aws/securityhub$"
        if re.match(pa_pattern, self.product_arn or ""):
            return
        id_match = re.match(
            r"^arn:(aws|aws-cn|aws-us-gov):securityhub:([a-z]{2}(?:-gov)?-[a-z]+-\d):",
            self.finding_id or "",
        )
        if id_match:
            self.product_arn = f"arn:{id_match.group(1)}:securityhub:{id_match.group(2)}::product/aws/securityhub"
            self.finding_json["ProductArn"] = self.product_arn
            return
        self.valid_finding = False
        self.invalid_finding_reason = f"ProductArn is invalid: {self.product_arn}"

    def __init__(
        self,
        finding_json: dict[str, Any],
        parse_id_pattern: str,
        expected_control_id: list[str],
        resource_index: int,
    ) -> None:
        self.valid_finding = True
        self.resource_region = None
        self.control_id = None
        self.aws_config_rule_id: str | None = None
        self.aws_config_rule: dict[str, Any] = {}
        self.input_params = {}

        self.finding_json: Any = dict(finding_json)
        self._get_resource_id(parse_id_pattern, resource_index)
        self._get_standard_info()

        self.account_id = self.finding_json.get("AwsAccountId", None)
        if not re.match(r"^\d{12}$", self.account_id or "") and self.valid_finding:
            self.valid_finding = False
            self.invalid_finding_reason = f"AwsAccountId is invalid: {self.account_id}"
        self.finding_id = self.finding_json.get("Id", None)
        self.product_arn = self.finding_json.get("ProductArn", None)
        self._resolve_product_arn()
        self.details = self.finding_json["Resources"][0].get("Details", {})
        self.testmode = bool("testmode" in self.finding_json)
        self.resource = self.finding_json["Resources"][0]
        self._get_region_from_resource_id()
        self.aws_config_rule_id, self.aws_config_rule = self._fetch_aws_config_rule()

        if "InputParameters" in self.aws_config_rule:
            self.input_params = json.loads(self.aws_config_rule["InputParameters"])

        self.affected_object = {
            "Type": self.resource["Type"],
            "Id": self.resource_id,
            "OutputKey": "Remediation.Output",
        }

        if not self.control_id:
            if self.valid_finding:
                self.valid_finding = False
                self.invalid_finding_reason = f'Finding Id is invalid: {self.finding_json["Id"]} - missing Control Id'
        elif self.control_id not in expected_control_id and self.valid_finding:
            self.valid_finding = False
            self.invalid_finding_reason = f"Control Id from input ({self.control_id}) does not match {str(expected_control_id)}"

        if not self.resource_id and self.valid_finding:
            self.valid_finding = False
            self.invalid_finding_reason = (
                "Resource Id is missing from the finding json Resources (Id)"
            )

        if not self.valid_finding:
            msg = f"ERROR: {self.invalid_finding_reason}"
            exit(msg)

    def __str__(self):
        return json.dumps(self.__dict__)


def parse_event(event, _):
    finding_event = FindingEvent(
        event["Finding"],
        event["parse_id_pattern"],
        event["expected_control_id"],
        event.get("resource_index", 1),
    )

    if not finding_event.valid_finding:
        exit("ERROR: Finding is not valid")

    return {
        "account_id": finding_event.account_id,
        "resource_id": finding_event.resource_id,
        "finding_id": finding_event.finding_id,
        "control_id": finding_event.control_id,
        "product_arn": finding_event.product_arn,
        "object": finding_event.affected_object,
        "matches": finding_event.resource_id_matches,
        "details": finding_event.details,
        "testmode": finding_event.testmode,
        "resource": finding_event.resource,
        "resource_region": finding_event.resource_region,
        "finding": finding_event.finding_json,
        "aws_config_rule": finding_event.aws_config_rule,
        "input_params": finding_event.input_params,
    }
