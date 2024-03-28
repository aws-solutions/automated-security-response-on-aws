# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
from typing import Any

from layer.sechub_findings import Finding

from simtest.boto_session import get_session
from simtest.orchestrator import get_orchestrator


class ControlTest:
    def __init__(self):
        self.standard = ""
        self.control = ""
        self.description = ""
        self.test_json = {}
        self.orchestrator = get_orchestrator()

    def load_json(self, finding_json_filename, wrap_it_in_findings=False):
        self.test_json = read_remediation_json(finding_json_filename)
        if wrap_it_in_findings:
            self.test_json = wrap_in_findings(self.test_json)

    def create_finding(self):
        self.finding = Finding(self.test_json["detail"]["findings"][0])
        return

    def print_heading(self, description):
        print("=" * 80)
        print(
            f"Simulate {self.finding.standard_shortname} {self.finding.standard_control} Findings\n"
        )
        print(self.finding.title)
        print("-" * len(self.finding.title) + "\n")
        print(self.finding.description + "\n")
        print(self.finding.remediation_url + "\n")
        print("TEST\n----")
        print(f"{description}\n")
        return

    def print_verification_instructions(self, instructions):
        print("VERIFICATION\n------------")
        if type(instructions) is list:
            for line in instructions:
                print(line)
        else:
            print(instructions)
        print()

    def print_prep_instructions(self, instructions):
        print("PREPARATION\n-----------")
        if type(instructions) is list:
            for line in instructions:
                print(line)
        else:
            print(instructions)
        print()

    def run(self):
        continue_answer = input("Press enter to run the test or Q to quit: ")
        if continue_answer.lower() == "q":
            print("CANCELLED.")
            exit()

        self.orchestrator.invoke(self.test_json)


class RemediationTest:
    def __init__(self, remediation, account, wrap_it_in_findings=False):
        self.remediation = remediation
        self.test_json = read_remediation_json(self.remediation)
        if wrap_it_in_findings:
            self.test_json = wrap_in_findings(self.test_json)
        self.orchestrator = get_orchestrator()

        self.test_json["detail"]["findings"][0]["AwsAccountId"] = account
        self.test_json["detail"]["findings"][0]["Resources"][0][
            "Region"
        ] = self.orchestrator.get_region()

        # If submitting a finding in the orchestrator account, we can substitute the config rule ID
        # Otherwise, the config rule ID must be substituted manually with the ID from the finding account
        if account == get_session().get_account():
            self._substitute_config_rules()

    def _substitute_config_rules(self):
        rule_store = ConfigRuleStore()
        finding = self.test_json["detail"]["findings"][0]
        resource_index = 0
        type_key = f"RelatedAWSResources:{str(resource_index)}/type"
        name_key = f"RelatedAWSResources:{str(resource_index)}/name"
        while finding.get("ProductFields", {}).get(type_key, None):
            if finding["ProductFields"][type_key] == "AWS::Config::ConfigRule":
                rule_name = finding["ProductFields"][name_key]
                rule_name_prefix = rule_name[
                    0 : len(rule_name) - len(rule_name.split("-")[-1])
                ]
                finding["ProductFields"][name_key] = (
                    rule_store.get_rule_name_from_prefix(rule_name_prefix)
                )
            resource_index = resource_index + 1
            type_key = f"RelatedAWSResources:{str(resource_index)}/type"
            name_key = f"RelatedAWSResources:{str(resource_index)}/name"

    def run(self):
        self.orchestrator.invoke(self.test_json)


class ConfigRuleStore:
    def __init__(self):
        self._session = get_session()

    def get_rule_name_from_prefix(self, prefix):
        rules = self._list_rules()
        for rule in rules:
            if rule["ConfigRuleName"].startswith(prefix):
                return rule["ConfigRuleName"]
        return None

    # TODO can cache locally by profile, these don't change often
    def _list_rules(self):
        config_client = self._session.client("config")
        response = config_client.describe_config_rules()
        rules = response["ConfigRules"]
        token = response.get("NextToken", None)
        while token:
            response = config_client.describe_config_rules(NextToken=token)
            rules.extend(response["ConfigRules"])
            token = response.get("NextToken", None)
        return rules


def wrap_in_findings(test_json):
    wrapper: Any = {
        "version": "0",
        "id": "609185ea-be02-2b86-4187-ce81f45b82a9",
        "detail-type": "Security Hub Findings - Custom Action",
        "source": "aws.securityhub",
        "account": "111111111111",
        "time": "2020-06-24T20:06:09Z",
        "region": "us-east-2",
        "resources": ["arn:aws:securityhub:us-east-2:111111111111:action/custom/foo"],
        "detail": {
            "actionName": "foo",
            "actionDescription": "foo bar baz",
            "findings": [],
        },
    }
    wrapper["detail"]["findings"].append(test_json)
    return wrapper


def read_remediation_json(remediation):
    sample_json = "./simdata/" + remediation + ".json"
    fh = open(sample_json, mode="r")
    return json.loads(fh.read())
