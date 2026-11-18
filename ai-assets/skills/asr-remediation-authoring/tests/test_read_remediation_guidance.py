# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for read_remediation_guidance.py.

The fixtures are sanitized `GetRemediationsV2` (ShowGuidance=true) responses captured from a
real account (account ID and resource names replaced), so the shapes, the comma-separated
multi-service steps, and the guidance defaults are the ones Security Hub actually returns.
"""
from __future__ import annotations

import copy
import functools
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import read_remediation_guidance as reader
from conftest import FIXTURES_DIR, SCRIPTS_DIR

GUIDANCE_DIR = FIXTURES_DIR / "remediation-guidance"
SCRIPT = SCRIPTS_DIR / "read_remediation_guidance.py"


def _load(name: str) -> dict[str, Any]:
    response: dict[str, Any] = json.loads((GUIDANCE_DIR / f"{name}.json").read_text())
    return response


def _fix_step(response: dict[str, Any]) -> dict[str, Any]:
    return next(
        step
        for step in response["Items"][0]["Guidance"]["Specification"]["Steps"]
        if step["Phase"] == "FIX"
    )


def _run(*args: str) -> tuple[int, dict[str, Any]]:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, json.loads(proc.stdout)


class TestGate:
    def test_object_lock_is_refused_for_every_reason_the_guidance_gives(self) -> None:
        """S3.15 guidance needs a person, is only partially automatable, and builds a new bucket.

        Each is an independent reason an ASR Custom Runbook must not be generated from it; the
        last one also means the finding's own bucket would stay non-compliant.
        """
        report = reader.build_report(_load("s3-object-lock"))

        assert report["gate"]["automatable"] is False
        reasons = " ".join(report["gate"]["reasons"])
        assert "HumanReviewRequired" in reasons
        assert "'partial'" in reasons
        assert "s3:CreateBucket" in reasons and "replacement resource" in reasons
        assert report["generateRunbookGuidance"] is None

    def test_object_lock_cli_exits_3(self) -> None:
        """Exit 3 lets a host tell a refusal from an error (2) without parsing the report."""
        code, report = _run("--input-file", str(GUIDANCE_DIR / "s3-object-lock.json"))
        assert code == reader.EXIT_REFUSED
        assert report["gate"]["automatable"] is False

    @pytest.mark.parametrize("name", ["s3-sse-kms", "dynamodb-backup-plan"])
    def test_fully_automatable_guidance_passes(self, name: str) -> None:
        code, report = _run("--input-file", str(GUIDANCE_DIR / f"{name}.json"))
        assert code == reader.EXIT_AUTOMATABLE
        assert report["gate"] == {"automatable": True, "reasons": []}

    def test_resolved_target_is_refused(self) -> None:
        """A Resolved target has nothing left to fix; generating a runbook for it is wasted work."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Status"] = "Resolved"
        assert "already Resolved" in " ".join(
            reader.build_report(response)["gate"]["reasons"]
        )

    def test_target_without_guidance_is_refused(self) -> None:
        """Without ShowGuidance the item has no Guidance; there is nothing to author from."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        del response["Items"][0]["Guidance"]
        report = reader.build_report(response)
        assert report["gate"]["automatable"] is False
        assert "ShowGuidance" in report["gate"]["reasons"][0]

    def test_fix_without_a_service_is_refused_instead_of_passing_unchecked(
        self,
    ) -> None:
        """A FIX that names no Service builds no service:Action, so nothing else would be checked."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        _fix_step(response).pop("Service")
        report = reader.build_report(response)

        assert report["gate"]["automatable"] is False
        assert "No FIX step names an API action" in " ".join(report["gate"]["reasons"])
        assert report["generateRunbookGuidance"] is None

    def test_replacement_is_caught_even_without_a_fix_service(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        fix = _fix_step(response)
        fix.pop("Service")
        fix["Action"] = "CreateBucket"

        reasons = " ".join(reader.build_report(response)["gate"]["reasons"])

        assert "replacement resource (CreateBucket)" in reasons

    @pytest.mark.parametrize(
        "service, action",
        [
            ("dynamodb", "RestoreTableToPointInTime"),
            ("s3", "CreateBucket"),
            ("rds", "RestoreDBInstanceToPointInTime"),
            ("ec2", "RunInstances"),
        ],
    )
    def test_a_fix_that_builds_a_new_resource_is_a_replacement(
        self, service: str, action: str
    ) -> None:
        """Restore, Copy, Run and Create-of-the-same-type build a new resource, so the finding's
        resource would stay non-compliant, whether or not the action is listed anywhere.
        """
        response = copy.deepcopy(_load("s3-sse-kms"))
        fix = _fix_step(response)
        fix["Service"], fix["Action"] = service, action

        reasons = " ".join(reader.build_report(response)["gate"]["reasons"])

        assert f"replacement resource ({service}:{action})" in reasons

    @pytest.mark.parametrize(
        "action", ["PublishVersion", "RegisterTaskDefinition", "Invoke"]
    )
    def test_an_unrecognized_fix_verb_is_refused(self, action: str) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        _fix_step(response)["Action"] = action

        gate = reader.build_report(response)["gate"]

        assert gate["automatable"] is False
        assert f"s3:{action}, which is not a verb known to change" in " ".join(
            gate["reasons"]
        )

    def test_a_fix_that_deletes_the_finding_resource_is_refused(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        _fix_step(response)["Action"] = "DeleteBucket"

        reasons = " ".join(reader.build_report(response)["gate"]["reasons"])

        assert "deletes the resource in the finding" in reasons
        assert "(s3:DeleteBucket)" in reasons

    @pytest.mark.parametrize("phase", ["SNAPSHOT", "VERIFY", "CLEANUP"])
    def test_a_write_outside_the_fix_steps_is_refused(self, phase: str) -> None:
        """Only FIX actions are judged by verb, so a write in any other step (including a phase
        the reader does not know) must refuse instead of passing unchecked."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        steps = response["Items"][0]["Guidance"]["Specification"]["Steps"]
        steps.append({"Phase": phase, "Service": "s3", "Action": "DeleteBucket"})

        gate = reader.build_report(response)["gate"]

        assert gate["automatable"] is False
        assert "only FIX steps may change resources" in " ".join(gate["reasons"])

    def test_create_without_a_resource_type_is_refused(self) -> None:
        """CreateBackupPlan is fine for a table, but without ResourceType it cannot be told
        apart from a replacement."""
        response = copy.deepcopy(_load("dynamodb-backup-plan"))
        response["Items"][0]["Guidance"]["Metadata"].pop("ResourceType")

        gate = reader.build_report(response)["gate"]

        assert gate["automatable"] is False
        assert "backup:CreateBackupPlan" in " ".join(gate["reasons"])

    @pytest.mark.parametrize(
        "name, resource_type, kind",
        [
            ("s3:PutBucketEncryption", "AWS::S3::Bucket", "in-place"),
            ("dynamodb:UpdateTable", "AWS::DynamoDB::Table", "in-place"),
            ("backup:CreateBackupSelection", "AWS::DynamoDB::Table", "in-place"),
            ("s3:CreateBucketPolicy", "AWS::S3::Bucket", "in-place"),
            ("dynamodb:CreateTable", "AWS::DynamoDB::Table", "replacement"),
            ("s3:CreateBucket", "AWS::S3::Bucket", "replacement"),
            ("s3:CopyObject", "AWS::S3::Bucket", "replacement"),
            ("Settle", "AWS::S3::Bucket", "unrecognized"),
            ("s3:putBucketEncryption", "AWS::S3::Bucket", "unrecognized"),
            # The resource type matches ignoring case and separators, in either spelling.
            ("ec2:CreateVpc", "AWS::EC2::VPC", "replacement"),
            ("s3:CreateBucket", "AwsS3Bucket", "replacement"),
            ("ec2:CreateVpcEndpoint", "AWS::EC2::VPC", "in-place"),
            # Common in-place fixes, as ASR's own built-in runbooks call them.
            ("ec2:RevokeSecurityGroupIngress", "AWS::EC2::SecurityGroup", "in-place"),
            ("ec2:AuthorizeSecurityGroupEgress", "AWS::EC2::SecurityGroup", "in-place"),
            ("cloudtrail:StartLogging", "AWS::CloudTrail::Trail", "in-place"),
            ("secretsmanager:RotateSecret", "AWS::SecretsManager::Secret", "in-place"),
            # Delete passes for a part of the resource, never for the resource or its data.
            ("s3:DeleteBucketPolicy", "AWS::S3::Bucket", "in-place"),
            ("iam:DeleteLoginProfile", "AWS::IAM::User", "in-place"),
            ("iam:DeleteAccessKey", "AWS::IAM::User", "in-place"),
            ("s3:DeleteBucket", "AWS::S3::Bucket", "destructive"),
            ("iam:DeleteUser", "AwsIamUser", "destructive"),
            ("s3:DeleteObjects", "AWS::S3::Bucket", "destructive"),
            ("s3:DeleteBucketPolicy", None, "unrecognized"),
            # Found by classifying every botocore operation: these passed as in-place before.
            ("backup:StartRestoreJob", "AWS::DynamoDB::Table", "replacement"),
            ("backup:StartCopyJob", "AWS::Backup::RecoveryPoint", "replacement"),
            ("rds:CreateDBInstanceReadReplica", "AWS::RDS::DBInstance", "replacement"),
            ("dynamodb:CreateTableReplica", "AWS::DynamoDB::Table", "replacement"),
            ("ec2:CreateDefaultVpc", "AWS::EC2::VPC", "replacement"),
            ("backup:DeleteBackupPlan", "AWS::DynamoDB::Table", "destructive"),
            ("rds:DeleteDBClusterSnapshot", "AWS::RDS::DBCluster", "destructive"),
            ("backup:DeleteRecoveryPoint", "AWS::DynamoDB::Table", "destructive"),
            ("ec2:DeleteVolume", "AWS::EC2::Instance", "destructive"),
            # Spaces and punctuation in the guidance text do not hide the name.
            ("s3:Create Bucket", "AWS::S3::Bucket", "replacement"),
            ("CreateBucket()", "AWS::S3::Bucket", "replacement"),
            ("s3:Delete-Bucket", "AWS::S3::Bucket", "destructive"),
            # Plural API names still name the finding's own type.
            ("ec2:DeleteVpcEndpoints", "AWS::EC2::VPCEndpoint", "destructive"),
            ("cloudwatch:DeleteAlarms", "AWS::CloudWatch::Alarm", "destructive"),
            ("ssm:DeleteParameters", "AWS::SSM::Parameter", "destructive"),
            ("ec2:DeleteSecurityGroup", "AwsEc2SecurityGroup", "destructive"),
            # A parent or unrelated resource is neither part of the finding's resource nor on the
            # known-safe list, so it is refused.
            ("ec2:DeleteVpc", "AWS::EC2::Subnet", "unrecognized"),
            ("eks:DeleteCluster", "AWS::EKS::Nodegroup", "unrecognized"),
            # Found before publishing revision 4: these passed as in-place.
            ("ec2:DeleteKeyPair", "AwsIamAccessKey", "other-resource"),
            ("iam:DeleteGroupPolicy", "AwsEc2SecurityGroup", "other-resource"),
            ("lightsail:DeleteBucketAccessKey", "AWS::S3::Bucket", "other-resource"),
            ("iam:PutRolePolicy", "AWS::S3::Bucket", "other-resource"),
            ("s3:PutBucketPolicy", "AWS::DynamoDB::Table", "other-resource"),
            ("PutBucketPolicy", "AWS::S3::Bucket", "other-resource"),
            ("s3:PutObject", "AWS::S3::Bucket", "destructive"),
            ("dynamodb:UpdateItem", "AWS::DynamoDB::Table", "destructive"),
            ("s3:PutBucketEncryption", "AwsS3Bucket", "in-place"),
            ("cloudtrail:StartLogging", "AwsCloudTrailTrail", "in-place"),
            # IAM prefixes the resource type spells differently.
            ("es:UpdateDomainConfig", "AWS::OpenSearchService::Domain", "in-place"),
            ("es:UpdateDomainConfig", "AwsOpenSearchServiceDomain", "in-place"),
            (
                "es:UpdateElasticsearchDomainConfig",
                "AwsElasticsearchDomain",
                "in-place",
            ),
            ("elasticfilesystem:PutBackupPolicy", "AWS::EFS::FileSystem", "in-place"),
            (
                "states:UpdateStateMachine",
                "AWS::StepFunctions::StateMachine",
                "in-place",
            ),
            (
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                "AwsElbv2LoadBalancer",
                "in-place",
            ),
            ("cognito-idp:UpdateUserPool", "AWS::Cognito::UserPool", "in-place"),
            ("es:UpdateDomainConfig", "AWS::S3::Bucket", "other-resource"),
            ("es:UpdateDomainConfig", "AwsSesConfigurationSet", "other-resource"),
            ("ec2:ModifyInstanceAttribute", "AWS::EKS::Nodegroup", "other-resource"),
            ("sns:CreateTopic", "AWS::S3::Bucket", "other-resource"),
        ],
    )
    def test_fix_change_kind_is_decided_by_the_whole_leading_verb(
        self, name: str, resource_type: str | None, kind: str
    ) -> None:
        """`Settle` must not pass as `Set`, and a verb in an unexpected case fails closed."""
        assert reader.fix_change_kind(name, resource_type) == kind

    def test_human_review_alone_refuses_otherwise_full_guidance(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"]["HumanReviewRequired"] = True

        gate = reader.build_report(response)["gate"]

        assert gate == {
            "automatable": False,
            "reasons": [
                "Guidance sets HumanReviewRequired: a person must decide this remediation."
            ],
        }

    def test_missing_automation_level_fails_closed(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"].pop("AutomationLevel")

        assert "AutomationLevel is None" in " ".join(
            reader.build_report(response)["gate"]["reasons"]
        )


@functools.lru_cache(maxsize=1)
def _every_aws_operation() -> list[str]:
    session = pytest.importorskip("botocore.session").get_session()
    names: set[str] = set()
    for service in session.get_available_services():
        names.update(session.get_service_model(service).operation_names)
    return sorted(names)


class TestGateAgainstEveryAwsOperation:
    """Classify every operation botocore knows, so a name pattern no hand-picked example covers
    cannot pass the FIX check. Runs offline from botocore's bundled service models."""

    @staticmethod
    def _operations() -> list[str]:
        return _every_aws_operation()

    def test_creating_or_deleting_the_finding_resource_type_never_passes(self) -> None:
        passed = [
            f"{name} on {resource_type}"
            for name in self._operations()
            if name.startswith(("Create", "Delete"))
            for resource_type in (f"AWS::Svc::{name[6:]}", f"AwsSvc{name[6:]}")
            if reader.fix_change_kind(name, resource_type) == "in-place"
        ]
        assert passed == []

    def test_no_create_or_start_that_names_a_copy_passes(self) -> None:
        words = reader.REPLACEMENT_WORDS
        passed = [
            name
            for name in self._operations()
            if name.startswith(("Create", "Start"))
            and set(reader.NAME_WORDS.findall(name)[1:]) & words
            and reader.fix_change_kind(name, "AWS::Svc::Thing") == "in-place"
        ]
        assert passed == []

    def test_a_create_or_delete_passes_only_for_a_part_or_a_known_safe_call(
        self,
    ) -> None:
        """A Create/Delete that neither starts with the resource's noun nor is on the safe list
        (a parent, a sibling, an unrelated resource) must never pass."""
        passed = [
            name
            for name in self._operations()
            if name.startswith(("Create", "Delete"))
            and not name[6:].lower().startswith("thing")
            and reader.fix_change_kind(name, "AWS::Svc::Thing") == "in-place"
            and f":{name}"
            not in {a[a.index(":") :] for a in reader.SAFE_CREATE_DELETE_ACTIONS}
        ]
        assert passed == []

    def test_no_delete_that_names_data_passes(self) -> None:
        passed = [
            name
            for name in self._operations()
            if name.startswith("Delete")
            and set(reader.NAME_WORDS.findall(name)[1:]) & reader.DATA_WORDS
            and reader.fix_change_kind(name, "AWS::Svc::Thing") == "in-place"
        ]
        assert passed == []


def _lowercase_keys(value: Any) -> Any:
    """The same response with every key in lowerCamelCase, as a future API might spell them."""
    if isinstance(value, dict):
        return {
            key[:1].lower() + key[1:]: _lowercase_keys(inner)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [_lowercase_keys(inner) for inner in value]
    return value


JsonPath = tuple[str | int, ...]


def _paths(value: Any, prefix: JsonPath = ()) -> list[JsonPath]:
    """Every key path in a nested JSON value, outermost first."""
    found: list[JsonPath] = []
    children = (
        value.items()
        if isinstance(value, dict)
        else enumerate(value) if isinstance(value, list) else []
    )
    for key, inner in children:
        found.append(prefix + (key,))
        found.extend(_paths(inner, prefix + (key,)))
    return found


def _replaced(response: dict[str, Any], path: JsonPath, new: Any) -> dict[str, Any]:
    """A deep copy of the response with the value at `path` replaced by `new`."""
    copied = copy.deepcopy(response)
    node: Any = copied
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = new
    return copied


class TestApiDrift:
    """A changed GetRemediationsV2 response must never crash the script or loosen the gate."""

    @pytest.mark.parametrize("status", ["RESOLVED", "resolved"])
    def test_resolved_in_any_case_is_refused(self, status: str) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Status"] = status

        assert "already Resolved" in " ".join(
            reader.build_report(response)["gate"]["reasons"]
        )

    def test_human_review_as_text_is_refused(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"]["HumanReviewRequired"] = "true"

        assert "a person must decide" in " ".join(
            reader.build_report(response)["gate"]["reasons"]
        )

    def test_unreadable_human_review_is_treated_as_required(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"]["HumanReviewRequired"] = "maybe"

        report = reader.build_report(response)

        assert report["gate"]["automatable"] is False
        assert "treating it as required" in " ".join(report["gate"]["reasons"])
        assert any(
            "HumanReviewRequired" in warning for warning in report["schemaWarnings"]
        )

    def test_missing_human_review_is_treated_as_required(self) -> None:
        """A renamed or dropped field must not silently remove the human-review requirement."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"].pop("HumanReviewRequired")

        report = reader.build_report(response)

        assert report["gate"] == {
            "automatable": False,
            "reasons": [
                "Guidance HumanReviewRequired is missing or cannot be read; treating it as required."
            ],
        }
        assert (
            "Guidance.Metadata.HumanReviewRequired is missing; treated as required."
            in report["schemaWarnings"]
        )

    def test_an_unknown_step_phase_never_counts_as_fix(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        _fix_step(response)["Phase"] = "REMEDIATE"

        report = reader.build_report(response)

        assert report["gate"]["automatable"] is False
        assert any("REMEDIATE" in warning for warning in report["schemaWarnings"])

    def test_wrongly_typed_steps_and_specification_refuse_instead_of_crashing(
        self,
    ) -> None:
        steps_broken = copy.deepcopy(_load("s3-sse-kms"))
        steps_broken["Items"][0]["Guidance"]["Specification"]["Steps"] = [
            "not a step",
            7,
        ]
        spec_broken = copy.deepcopy(_load("s3-sse-kms"))
        spec_broken["Items"][0]["Guidance"]["Specification"] = "not an object"

        for response in (steps_broken, spec_broken):
            report = reader.build_report(response)
            assert report["gate"]["automatable"] is False
            assert report["schemaWarnings"]

    def test_tolerated_shape_changes_give_the_same_report(self) -> None:
        original = reader.build_report(_load("dynamodb-backup-plan"))
        list_actions = copy.deepcopy(_load("dynamodb-backup-plan"))
        for step in list_actions["Items"][0]["Guidance"]["Specification"]["Steps"]:
            step["Action"] = [part.strip() for part in step["Action"].split(",")]
            step["Phase"] = step["Phase"].lower()
        spec = list_actions["Items"][0]["Guidance"]["Specification"]
        spec["RequiredPermissions"] = ", ".join(spec["RequiredPermissions"])
        list_actions["Items"][0]["Guidance"]["Metadata"]["AutomationLevel"] = "FULL"
        list_actions["Items"][0]["NewFieldFromAFutureApi"] = {"anything": [1, 2]}

        for response in (list_actions, _lowercase_keys(_load("dynamodb-backup-plan"))):
            report = reader.build_report(response)
            assert report["gate"] == original["gate"]
            assert report["iamActions"] == original["iamActions"]
            assert (
                report["generateRunbookGuidance"] == original["generateRunbookGuidance"]
            )
            assert report["rollback"]["candidate"] == original["rollback"]["candidate"]

    @pytest.mark.parametrize(
        "name", ["s3-sse-kms", "dynamodb-backup-plan", "s3-object-lock"]
    )
    def test_no_single_field_change_crashes_or_loosens_the_gate(
        self, name: str
    ) -> None:
        """Replace each field, one at a time, with each wrong type.

        A fixture has about 100 paths and there are 7 wrong values, so this runs build_report about
        700 times per fixture; it stays well under a second because nothing touches the network.
        """
        response = _load(name)
        refused = not reader.build_report(response)["gate"]["automatable"]
        wrong_values: tuple[object, ...] = (None, 0, True, "x", [], {}, [None])
        for path in _paths(response):
            for wrong in wrong_values:
                try:
                    report = reader.build_report(_replaced(response, path, wrong))
                except LookupError:
                    continue  # no single target left: reported as exit 2
                json.dumps(report, default=str)
                if refused:
                    assert report["gate"]["automatable"] is False, (path, wrong)


class TestIamActions:
    def test_s3_api_names_are_translated_to_iam_action_names(self) -> None:
        """Guidance lists s3:GetBucketEncryption, but IAM checks s3:GetEncryptionConfiguration.

        A role built from the untranslated list is denied on its first call, and IAM accepts the
        unknown action names without complaint, so this only shows up at execution time.
        """
        iam = reader.build_report(_load("s3-sse-kms"))["iamActions"]

        assert iam["actions"] == [
            "kms:DescribeKey",
            "s3:GetEncryptionConfiguration",
            "s3:PutEncryptionConfiguration",
        ]
        assert iam["translated"]["s3:GetBucketEncryption"] == [
            "s3:GetEncryptionConfiguration"
        ]
        assert "s3:GetBucketEncryption" not in iam["actions"]

    def test_multi_service_steps_resolve_each_action_to_its_own_service(self) -> None:
        """'dynamodb, backup' with 'DescribeTable, ListBackupPlans, ListBackupSelections' does not
        pair by position; pairing that way invents backup:DescribeTable and dynamodb:GetBackupPlan.
        """
        report = reader.build_report(_load("dynamodb-backup-plan"))

        all_actions = {action for step in report["steps"] for action in step["actions"]}
        assert {
            "dynamodb:DescribeTable",
            "backup:ListBackupPlans",
            "backup:GetBackupPlan",
        } <= all_actions
        assert (
            not {
                "backup:DescribeTable",
                "dynamodb:GetBackupPlan",
                "dynamodb:ListBackupSelections",
            }
            & all_actions
        )

    def test_get_backup_selection_is_added_when_only_list_is_granted(self) -> None:
        """ListBackupSelections returns summaries without resources, so checking whether a table is
        covered needs GetBackupSelection, which the guidance's RequiredPermissions omits.
        """
        iam = reader.build_report(_load("dynamodb-backup-plan"))["iamActions"]
        assert "backup:GetBackupSelection" in iam["actions"]
        assert iam["implied"] == {
            "backup:ListBackupSelections": ["backup:GetBackupSelection"]
        }

    def test_copy_object_needs_both_get_and_put(self) -> None:
        assert reader.translate_iam_actions(["s3:CopyObject"])["actions"] == [
            "s3:GetObject",
            "s3:PutObject",
        ]

    def test_unknown_names_pass_through_unchanged(self) -> None:
        assert reader.translate_iam_actions(["dynamodb:UpdateTable"])["actions"] == [
            "dynamodb:UpdateTable"
        ]

    def test_an_action_that_already_names_its_service_is_not_prefixed_again(
        self,
    ) -> None:
        assert reader.split_actions(
            "s3", "s3:GetBucketEncryption, PutBucketEncryption"
        ) == [
            "s3:GetBucketEncryption",
            "s3:PutBucketEncryption",
        ]

    def test_a_delete_api_name_maps_to_the_put_action_iam_checks(self) -> None:
        actions = reader.translate_iam_actions(["s3:DeleteBucketEncryption"])["actions"]
        assert actions == ["s3:PutEncryptionConfiguration"]

    def test_single_service_steps_split_on_commas(self) -> None:
        assert reader.split_actions(
            "s3", "GetBucketVersioning, PutBucketVersioning"
        ) == ["s3:GetBucketVersioning", "s3:PutBucketVersioning"]
        assert reader.split_actions(None, "GetBucketVersioning") == []


class TestGenerateRunbookGuidance:
    def test_maps_to_the_generate_runbook_guidance_shape(self) -> None:
        """Matches RemediationGuidanceInputSchema (apiCall, requiredPermissions, resourceType,
        verifyAction), so the object can be passed straight to generate_runbook."""
        guidance = reader.build_report(_load("s3-sse-kms"))["generateRunbookGuidance"]

        assert guidance == {
            "apiCall": {"service": "s3", "action": "PutBucketEncryption"},
            "requiredPermissions": [
                "kms:DescribeKey",
                "s3:GetEncryptionConfiguration",
                "s3:PutEncryptionConfiguration",
            ],
            "resourceType": "AWS::S3::Bucket",
            "verifyAction": "GetBucketEncryption",
        }


class TestRollbackContext:
    def test_sse_kms_inverse_maps_to_the_iam_action_a_rollback_needs(self) -> None:
        """The Inverse restores with PutBucketEncryption or DeleteBucketEncryption; IAM checks both as
        s3:PutEncryptionConfiguration, the grant a rollback-capable S3.17 role was tested with.
        """
        rollback = reader.build_report(_load("s3-sse-kms"))["rollback"]

        assert rollback["candidate"] is True
        assert rollback["reversibility"] == "Fully reversible"
        assert rollback["inverseSteps"][0]["calls"] == [
            "s3:DeleteBucketEncryption",
            "s3:PutBucketEncryption",
        ]
        assert rollback["iamActions"] == ["s3:PutEncryptionConfiguration"]

    def test_backup_plan_inverse_warns_that_delete_backup_plan_is_rejected(
        self,
    ) -> None:
        """AWS Backup rejects DeleteBackupPlan while a selection exists, so the guidance Inverse as written
        cannot roll back, and on a shared plan it would target other resources' protection.
        """
        rollback = reader.build_report(_load("dynamodb-backup-plan"))["rollback"]

        assert rollback["candidate"] is True
        assert {"backup:DeleteBackupPlan", "backup:DeleteBackupSelection"} <= set(
            rollback["iamActions"]
        )
        assert any(
            "rejects DeleteBackupPlan while selections exist" in w
            for w in rollback["warnings"]
        )

    def test_refused_remediation_with_a_whole_bucket_delete_is_not_a_rollback_candidate(
        self,
    ) -> None:
        rollback = reader.build_report(_load("s3-object-lock"))["rollback"]

        assert rollback["candidate"] is False
        reasons = " ".join(rollback["reasons"])
        assert "refused by the gate" in reasons
        assert "s3:DeleteBucket" in reasons
        assert rollback["iamActions"] == []

    def test_an_inverse_that_deletes_the_finding_resource_in_plural_is_refused(
        self,
    ) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        _fix_step(response)[
            "Inverse"
        ] = "Call s3:DeleteBuckets(Bucket=example) to restore."

        rollback = reader.build_report(response)["rollback"]

        assert rollback["candidate"] is False
        assert "s3:DeleteBuckets" in " ".join(rollback["reasons"])

    def test_not_reversible_guidance_is_not_a_rollback_candidate(self) -> None:
        """S3.14 versioning guidance says 'Not reversible' (it can only be suspended); ASR's built-in
        S3.14 offers no rollback either."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"]["Reversibility"] = "Not reversible"
        rollback = reader.build_report(response)["rollback"]

        assert rollback["candidate"] is False
        assert "Not reversible" in rollback["reasons"][0]

    def test_an_unprefixed_whole_resource_delete_in_the_inverse_is_refused(
        self,
    ) -> None:
        """An Inverse call without a service prefix must not inherit a service that hides the delete."""
        response = copy.deepcopy(_load("dynamodb-backup-plan"))
        _fix_step(response)[
            "Inverse"
        ] = "Call DeleteTable(TableName=example) to restore."

        rollback = reader.build_report(response)["rollback"]

        assert rollback["candidate"] is False
        assert "dynamodb:DeleteTable" in " ".join(rollback["reasons"])

    @pytest.mark.parametrize("reversibility", ["Irreversible", "No", None])
    def test_reversibility_outside_the_reversible_values_fails_closed(
        self, reversibility: str | None
    ) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["Guidance"]["Metadata"]["Reversibility"] = reversibility

        assert reader.build_report(response)["rollback"]["candidate"] is False

    def test_fix_without_inverse_is_not_a_rollback_candidate(self) -> None:
        response = copy.deepcopy(_load("s3-sse-kms"))
        for step in response["Items"][0]["Guidance"]["Specification"]["Steps"]:
            step.pop("Inverse", None)
        assert "No FIX step carries an Inverse" in " ".join(
            reader.build_report(response)["rollback"]["reasons"]
        )


class TestWarnings:
    def test_flags_the_hardcoded_target_and_reference_only_examples(self) -> None:
        warnings = " ".join(reader.build_report(_load("s3-sse-kms"))["warnings"])
        assert "Derive the resource from the Finding" in warnings
        assert "Examples are reference only" in warnings and "aws/s3" in warnings

    def test_flags_backup_defaults_that_only_the_console_creates_and_the_invalid_schedule(
        self,
    ) -> None:
        warnings = " ".join(
            reader.build_report(_load("dynamodb-backup-plan"))["warnings"]
        )
        assert "AWSBackupDefaultServiceRole" in warnings
        assert "Default backup vault" in warnings
        assert "increment of 24" in warnings
        assert "account ID" in warnings

    def test_live_responses_with_datetimes_do_not_crash_the_scan(self) -> None:
        """boto3 returns datetime objects where a saved response has strings."""
        response = copy.deepcopy(_load("s3-sse-kms"))
        response["Items"][0]["UpdatedAt"] = datetime.now(timezone.utc)
        response["Items"][0]["Guidance"]["Metadata"]["GeneratedAt"] = datetime.now(
            timezone.utc
        )
        assert reader.build_report(response)["gate"]["automatable"] is True


class TestErrors:
    def test_empty_response_is_an_error(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"Items": []}))
        code, report = _run("--input-file", str(empty))
        assert code == reader.EXIT_ERROR
        assert "no remediation target" in report["error"]

    def test_several_targets_are_an_error_instead_of_reading_only_the_first(
        self, tmp_path: Path
    ) -> None:
        item = _load("s3-sse-kms")["Items"][0]
        saved = tmp_path / "two.json"
        saved.write_text(json.dumps({"Items": [item, item]}))

        code, report = _run("--input-file", str(saved))

        assert code == reader.EXIT_ERROR
        assert "2 remediation targets" in report["error"]

    def test_requires_exactly_one_source(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == reader.EXIT_ERROR
        assert json.loads(proc.stdout)["error"].startswith("UsageError:")

    def test_fetch_uses_only_the_callers_default_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Access must stay with the caller's own IAM permissions: no assumed role, no explicit keys."""
        client_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        class FakeClient:
            def get_remediations_v2(self, **_kwargs: Any) -> dict[str, Any]:
                return _load("s3-sse-kms")

        def fake_client(*args: Any, **kwargs: Any) -> FakeClient:
            client_calls.append((args, kwargs))
            return FakeClient()

        import boto3

        monkeypatch.setattr(boto3, "client", fake_client)
        reader.fetch(target_uid="example-target", metadata_uid=None, region="us-east-1")

        assert client_calls == [(("securityhub",), {"region_name": "us-east-1"})]

    def test_an_aws_error_is_one_json_error(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from botocore.exceptions import ClientError

        class FailingClient:
            def get_remediations_v2(self, **_kwargs: Any) -> dict[str, Any]:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "GetRemediationsV2",
                )

        import boto3

        monkeypatch.setattr(boto3, "client", lambda *_args, **_kwargs: FailingClient())

        code = reader.main(["--target-uid", "example-target", "--region", "us-east-1"])

        assert code == reader.EXIT_ERROR
        assert "AccessDeniedException" in json.loads(capsys.readouterr().out)["error"]

    def test_fetch_requests_guidance_for_the_target(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The live path asks for guidance (ShowGuidance) by TargetUid and drops ResponseMetadata."""
        calls: list[dict[str, Any]] = []

        class FakeClient:
            def get_remediations_v2(self, **kwargs: Any) -> dict[str, Any]:
                calls.append(kwargs)
                return {
                    **_load("s3-sse-kms"),
                    "ResponseMetadata": {"HTTPStatusCode": 200},
                }

        import boto3

        monkeypatch.setattr(boto3, "client", lambda *_args, **_kwargs: FakeClient())
        response = reader.fetch(
            target_uid="example-target", metadata_uid=None, region="us-east-1"
        )
        assert calls == [{"ShowGuidance": True, "TargetUid": "example-target"}]
        assert "ResponseMetadata" not in response
