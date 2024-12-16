# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from unittest.mock import patch

import boto3
import cfnresponse
from botocore.config import Config
from enable_remediation_rules import lambda_handler
from moto import mock_aws

REGION = "us-east-1"
BOTO_CONFIG = Config(retries={"mode": "standard"}, region_name=REGION)


def setup(security_standard, security_standard_version, control_ids):
    events_client = boto3.client("events", config=BOTO_CONFIG)
    created_rules = []
    for control_id in control_ids:
        rule_name = (
            f"{security_standard}_{security_standard_version}_{control_id}_AutoTrigger"
        )
        events_client.put_rule(
            Name=rule_name,
            ScheduleExpression="cron(0 20 * * ? *)",
            State="DISABLED",
        )
        created_rules.append(rule_name)
    return created_rules


def verify_rules_enabled(rule_names):
    events_client = boto3.client("events", config=BOTO_CONFIG)
    for rule_name in rule_names:
        response = events_client.describe_rule(Name=rule_name)
        assert response["State"] == "ENABLED"


@patch("cfnresponse.send")
@mock_aws
def test_handler(mock_cfnresponse):
    security_standard = "SC"
    security_standard_version = "2.0.0"
    controls = ["S3.9", "KMS.4", "SecretsManager.1", "SQS.1"]
    rules = setup(security_standard, security_standard_version, controls)

    event = {
        "ResourceType": "Custom::EnableRemediationRules",
        "RequestType": "Create",
        "ResourceProperties": {
            "SecurityStandard": security_standard,
            "SecurityStandardVersion": security_standard_version,
        },
    }

    lambda_handler(
        event,
        None,
    )

    verify_rules_enabled(rules)
    mock_cfnresponse.assert_called_once_with(
        event, None, cfnresponse.SUCCESS, {}, reason=None
    )


@patch("cfnresponse.send")
@mock_aws
def test_handler_with_nonexistent_rules(mock_cfnresponse):
    security_standard = "SC"
    security_standard_version = "2.0.0"
    controls = ["KMS.4", "SecretsManager.1", "SQS.1"]
    rules = setup(security_standard, security_standard_version, controls)

    event = {
        "ResourceType": "Custom::EnableRemediationRules",
        "RequestType": "Create",
        "ResourceProperties": {
            "SecurityStandard": security_standard,
            "SecurityStandardVersion": security_standard_version,
        },
    }

    lambda_handler(
        event,
        None,
    )

    verify_rules_enabled(rules)
    mock_cfnresponse.assert_called_once_with(
        event, None, cfnresponse.FAILED, {}, reason="Failed to enable rules: ['S3.9']"
    )
