#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read Security Hub remediation plan guidance and turn it into runbook authoring input.

Calls Security Hub `GetRemediationsV2` with `ShowGuidance=true` for one remediation target
(or reads a saved response with `--input-file`) and reports:

- `gate` — whether the guidance may be turned into an automated Custom Runbook. It is
  refused when the guidance says a person must decide (`HumanReviewRequired` is true,
  missing or unreadable), when it is not fully automatable (`AutomationLevel` other
  than `full`), when the target is already `Resolved`, when no FIX step names an API
  action, or when a FIX does not change the resource in the finding in place: it
  creates a replacement, or its API verb is not one the gate recognizes.
- `iamActions` — the IAM actions to start the remediation role from. Guidance
  `RequiredPermissions` mixes API names with IAM action names (`s3:GetBucketEncryption`
  is an API; IAM checks `s3:GetEncryptionConfiguration`), so known API-to-action
  differences are translated. The list is a starting point: derive the final policy
  from the calls the handler actually makes (`remediation-iam.md`).
- `generateRunbookGuidance` — the `guidance` object `generate_runbook` accepts
  (`RemediationGuidanceInputSchema`), or null when the gate refuses.
- `rollback` — whether a rollback is worth authoring (`candidate`, `reasons`), the FIX
  steps' inverse calls, the IAM actions they need, and warnings where the inverse is
  unsafe as written.
- `warnings` — guidance properties that must not be copied into a runbook as-is.
- `schemaWarnings` — parts of the response that could not be read, for example after a
  Security Hub API change. Each one makes the gate stricter, never looser.

Usage:
    read_remediation_guidance.py (--target-uid UID | --metadata-uid UID | --input-file FILE)
                                 [--region <aws-region>]

Exit codes: 0 = automatable, 3 = refused by the gate (read `gate.reasons`),
2 = usage error, AWS error, or a response that is not exactly one target. Prints a JSON
report to stdout; every failure is a one-line `{"error": ...}`.
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import sys
from typing import Any, Literal, NoReturn, NotRequired, TypedDict

EXIT_AUTOMATABLE = 0
EXIT_ERROR = 2
EXIT_REFUSED = 3

# API names in Security Hub remediation plans that are not IAM actions, mapped to the IAM actions
# that authorize them (Service Authorization Reference). Only names seen in real plans are listed;
# any other name passes through unchanged, and a wrong one fails test_runbook.py with AccessDenied.
API_TO_IAM_ACTIONS: dict[str, tuple[str, ...]] = {
    "s3:GetBucketEncryption": ("s3:GetEncryptionConfiguration",),
    "s3:PutBucketEncryption": ("s3:PutEncryptionConfiguration",),
    "s3:DeleteBucketEncryption": ("s3:PutEncryptionConfiguration",),
    "s3:GetObjectLockConfiguration": ("s3:GetBucketObjectLockConfiguration",),
    "s3:PutObjectLockConfiguration": ("s3:PutBucketObjectLockConfiguration",),
    "s3:CopyObject": ("s3:GetObject", "s3:PutObject"),
}

# Actions a guidance step needs but its RequiredPermissions omits: a List call that returns only
# summaries, where the step's logic reads the full object (ListBackupSelections has no resource list,
# so checking whether a table is covered needs GetBackupSelection).
IMPLIED_ACTIONS: dict[str, tuple[str, ...]] = {
    "backup:ListBackupSelections": ("backup:GetBackupSelection",),
}

# A FIX must change the resource in the finding, and its API verb decides whether it does. Verbs
# that change a resource in place pass; verbs that build a new resource from the old one are
# replacements; any other verb is refused (fail closed). `Create` and `Delete` are judged against
# the finding's resource type: creating that type is a replacement and deleting it destroys the
# resource, while creating or deleting a part of it (CreateBucketPolicy, DeleteLoginProfile) passes.
IN_PLACE_VERBS = frozenset(
    {
        "Put",
        "Update",
        "Modify",
        "Enable",
        "Disable",
        "Set",
        "Tag",
        "Untag",
        "Add",
        "Remove",
        "Attach",
        "Detach",
        "Associate",
        "Disassociate",
        "Authorize",
        "Revoke",
        "Start",
        "Rotate",
    }
)
REPLACEMENT_VERBS = frozenset(
    {"Restore", "Copy", "Clone", "Duplicate", "Run", "Replicate"}
)
CREATE_VERB = "Create"
DELETE_VERB = "Delete"
# A Create or Start that names one of these builds a new resource from an existing one
# (StartRestoreJob, StartCopyJob, CreateDBInstanceReadReplica), so it is a replacement.
REPLACEMENT_WORDS = frozenset(
    {"Restore", "Copy", "Clone", "Duplicate", "Replica", "Replicate", "Import"}
)
# A Delete that names one of these destroys data or recovery points, not configuration.
DATA_WORDS = frozenset(
    {
        "Backup",
        "Backups",
        "Snapshot",
        "Snapshots",
        "Recovery",
        "Object",
        "Objects",
        "Version",
        "Versions",
        "Volume",
        "Volumes",
        "Image",
        "Images",
        "Archive",
    }
)
# Create/Delete calls that add or remove something attached to the finding's resource without
# being part of its name: a backup plan for a table, an IAM user's access key or console password,
# flow logs for a VPC. Any other Create/Delete must name a part of the resource (CreateBucketPolicy
# for a bucket) or the gate refuses it.
SAFE_CREATE_DELETE_ACTIONS = frozenset(
    {
        "backup:CreateBackupPlan",
        "backup:CreateBackupSelection",
        "iam:DeleteAccessKey",
        "iam:DeleteLoginProfile",
        "ec2:CreateFlowLogs",
        "logs:CreateLogGroup",
    }
)
# IAM service prefixes that the resource type spells differently, as CloudFormation
# (`AWS::OpenSearchService::Domain`) or Security Hub (`AwsElbv2LoadBalancer`) name them.
SERVICE_TYPE_NAMES: dict[str, tuple[str, ...]] = {
    "es": ("opensearchservice", "elasticsearch"),
    "elasticfilesystem": ("efs",),
    "states": ("stepfunctions",),
    "elasticloadbalancing": ("elb",),
    "elasticmapreduce": ("emr",),
    "macie2": ("macie",),
}
# The last word of an in-place call that writes data rather than configuration
# (PutObject, UpdateItem): refused like a delete of the resource's data.
DATA_WRITE_WORDS = frozenset(
    {"Object", "Objects", "Item", "Items", "Record", "Records"}
)
# Verbs that only read. Steps other than FIX (SNAPSHOT, VERIFY, or a phase the reader does not
# know) may call nothing else, so a write cannot hide in a step the FIX check does not look at.
READ_VERBS = frozenset(
    {"Get", "Describe", "List", "Head", "Lookup", "Search", "Query", "Scan", "Check"}
)

# Resources AWS creates only from the console, which guidance tends to assume exist.
CONSOLE_ONLY_DEFAULTS = {
    "AWSBackupDefaultServiceRole": "AWS creates AWSBackupDefaultServiceRole only from the console",
    "'Default'": "AWS creates the Default backup vault only from the console",
}


StepPhase = Literal["SNAPSHOT", "FIX", "VERIFY"]


# --- GetRemediationsV2 contract -------------------------------------------------------------
# Every field this script reads from the Security Hub response, in one place. Nothing below
# reads the raw response: `read_target` turns it into a `Target` first. Field names match
# case-insensitively, list fields also accept a comma-separated string, and anything that
# cannot be read becomes a `schemaWarnings` entry instead of an error. Whatever the reader
# cannot read makes the gate refuse (fail closed), so a changed API can only make this script
# stricter, never let unsafe guidance through.
FIELD_ITEMS = "Items"
FIELD_TARGET_UID = "TargetUid"
FIELD_STATUS = "Status"
FIELD_PRIORITY = "Priority"
FIELD_RESOURCE = "Resource"
FIELD_GUIDANCE = "Guidance"
FIELD_TARGET_TYPE_NAME = "TargetTypeName"
FIELD_METADATA = "Metadata"
FIELD_SPECIFICATION = "Specification"
FIELD_EXAMPLES = "Examples"
FIELD_HUMAN_REVIEW = "HumanReviewRequired"
FIELD_AUTOMATION_LEVEL = "AutomationLevel"
FIELD_REVERSIBILITY = "Reversibility"
FIELD_RESOURCE_TYPE = "ResourceType"
FIELD_STEPS = "Steps"
FIELD_REQUIRED_PERMISSIONS = "RequiredPermissions"
FIELD_PARAMETERS = "Parameters"
FIELD_EXPECTED_END_STATE = "ExpectedEndState"
FIELD_STEP_PHASE = "Phase"
FIELD_STEP_SERVICE = "Service"
FIELD_STEP_ACTION = "Action"
FIELD_STEP_DESCRIPTION = "Description"
FIELD_STEP_LOGIC = "Logic"
FIELD_STEP_VERIFY_AFTER = "VerifyAfter"
FIELD_STEP_INVERSE = "Inverse"
FIELD_RESOURCE_ID = "Id"
FIELD_RESOURCE_ACCOUNT_ID = "AccountId"

STEP_PHASES: dict[str, StepPhase] = {
    "snapshot": "SNAPSHOT",
    "fix": "FIX",
    "verify": "VERIFY",
}
RESOLVED_STATUS = "Resolved"
FULL_AUTOMATION = "full"
TRUE_WORDS = frozenset({"true", "yes"})
FALSE_WORDS = frozenset({"false", "no"})


class TargetStep(TypedDict):
    phase: StepPhase | None
    service: str
    action: str
    description: str | None
    logic: str | None
    verifyAfter: str | None
    inverse: str | None


class Target(TypedDict):
    """One remediation target as this script understands it, whatever shape the API returned."""

    targetUid: str | None
    status: str | None
    priority: str | None
    resource: dict[str, Any]
    resourceId: str
    resourceAccountId: str
    hasGuidance: bool
    guidance: dict[str, Any]
    targetTypeName: str | None
    metadata: dict[str, Any]
    humanReviewRequired: (
        bool | None
    )  # None when the field is absent or unreadable; the gate treats it as True
    automationLevel: str | None
    reversibility: str | None
    resourceType: str | None
    hasExamples: bool
    steps: list[TargetStep]
    requiredPermissions: list[str]
    parameters: list[dict[str, Any]]
    expectedEndState: str | None


class _Reader:
    """Reads loosely shaped JSON, recording in `warnings` what it could not use.

    Each method takes the raw value and the dotted path it came from (for the warning text) and
    returns the value in the shape the script needs, or an empty/None value when it cannot.
    """

    def __init__(self) -> None:
        self.warnings: list[str] = []

    def field(self, mapping: dict[str, Any], name: str) -> Any:
        if name in mapping:
            return mapping[name]
        lowered = name.lower()
        return next(
            (
                value
                for key, value in mapping.items()
                if isinstance(key, str) and key.lower() == lowered
            ),
            None,
        )

    def mapping(self, value: Any, path: str) -> dict[str, Any]:
        if value is None or isinstance(value, dict):
            return value or {}
        self.warnings.append(
            f"{path} is a {type(value).__name__}, not an object; ignored."
        )
        return {}

    def records(self, value: Any, path: str) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list):
            self.warnings.append(
                f"{path} is a {type(value).__name__}, not a list; ignored."
            )
            return []
        kept = [entry for entry in value if isinstance(entry, dict)]
        if len(kept) != len(value):
            self.warnings.append(
                f"{path} has {len(value) - len(kept)} entries that are not objects; skipped."
            )
        return kept

    def text(self, value: Any, path: str) -> str | None:
        if value is None or isinstance(value, str):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        self.warnings.append(f"{path} is a {type(value).__name__}, not text; ignored.")
        return None

    def names(self, value: Any, path: str) -> list[str]:
        """A list of names, given as a list or as one comma-separated string."""
        if value is None:
            return []
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        if isinstance(value, list):
            if any(not isinstance(part, str) for part in value):
                self.warnings.append(f"{path} has entries that are not text; skipped.")
            return [
                part.strip() for part in value if isinstance(part, str) and part.strip()
            ]
        self.warnings.append(
            f"{path} is a {type(value).__name__}, not a list of names; ignored."
        )
        return []

    def flag(self, value: Any, path: str) -> bool | None:
        if value is None or isinstance(value, bool):
            return value
        word = value.strip().lower() if isinstance(value, str) else None
        if word in TRUE_WORDS:
            return True
        if word in FALSE_WORDS:
            return False
        self.warnings.append(f"{path} is {value!r}, not true or false.")
        return None

    def phase(self, value: Any, path: str) -> StepPhase | None:
        """A step phase matched case-insensitively. An unknown phase is None, so it never counts as FIX."""
        word = self.text(value, path)
        if word is None:
            return None
        phase = STEP_PHASES.get(word.strip().lower())
        if phase is None:
            self.warnings.append(
                f"{path} has the unrecognized value {word!r}; the step is not treated as FIX."
            )
        return phase

    def status(self, value: Any, path: str) -> str | None:
        """The target status; `Resolved` is recognized in any letter case because the gate depends on it."""
        word = self.text(value, path)
        if word is not None and word.strip().lower() == RESOLVED_STATUS.lower():
            return RESOLVED_STATUS
        return word


def read_target(response: Any) -> tuple[Target, list[str]]:
    """The single remediation target in a `GetRemediationsV2` response, plus what could not be read."""
    reader = _Reader()
    root = reader.mapping(response, "response")
    items = reader.records(reader.field(root, FIELD_ITEMS), FIELD_ITEMS)
    if not items:
        raise LookupError("GetRemediationsV2 returned no remediation target")
    if len(items) > 1:
        raise LookupError(
            f"GetRemediationsV2 returned {len(items)} remediation targets; read one at a time with --target-uid"
        )
    item = items[0]
    guidance = reader.mapping(reader.field(item, FIELD_GUIDANCE), FIELD_GUIDANCE)
    metadata = reader.mapping(
        reader.field(guidance, FIELD_METADATA), f"{FIELD_GUIDANCE}.{FIELD_METADATA}"
    )
    specification = reader.mapping(
        reader.field(guidance, FIELD_SPECIFICATION),
        f"{FIELD_GUIDANCE}.{FIELD_SPECIFICATION}",
    )
    resource = reader.mapping(reader.field(item, FIELD_RESOURCE), FIELD_RESOURCE)
    steps_path = f"{FIELD_GUIDANCE}.{FIELD_SPECIFICATION}.{FIELD_STEPS}"
    steps: list[TargetStep] = []
    for index, step in enumerate(
        reader.records(reader.field(specification, FIELD_STEPS), steps_path)
    ):
        step_path = f"{steps_path}[{index}]"
        steps.append(
            {
                "phase": reader.phase(
                    reader.field(step, FIELD_STEP_PHASE),
                    f"{step_path}.{FIELD_STEP_PHASE}",
                ),
                "service": ", ".join(
                    reader.names(
                        reader.field(step, FIELD_STEP_SERVICE),
                        f"{step_path}.{FIELD_STEP_SERVICE}",
                    )
                ),
                "action": ", ".join(
                    reader.names(
                        reader.field(step, FIELD_STEP_ACTION),
                        f"{step_path}.{FIELD_STEP_ACTION}",
                    )
                ),
                "description": reader.text(
                    reader.field(step, FIELD_STEP_DESCRIPTION),
                    f"{step_path}.{FIELD_STEP_DESCRIPTION}",
                ),
                "logic": reader.text(
                    reader.field(step, FIELD_STEP_LOGIC),
                    f"{step_path}.{FIELD_STEP_LOGIC}",
                ),
                "verifyAfter": reader.text(
                    reader.field(step, FIELD_STEP_VERIFY_AFTER),
                    f"{step_path}.{FIELD_STEP_VERIFY_AFTER}",
                ),
                "inverse": reader.text(
                    reader.field(step, FIELD_STEP_INVERSE),
                    f"{step_path}.{FIELD_STEP_INVERSE}",
                ),
            }
        )
    level = reader.text(
        reader.field(metadata, FIELD_AUTOMATION_LEVEL), FIELD_AUTOMATION_LEVEL
    )
    human_review_path = f"{FIELD_GUIDANCE}.{FIELD_METADATA}.{FIELD_HUMAN_REVIEW}"
    raw_human_review = reader.field(metadata, FIELD_HUMAN_REVIEW)
    human_review = reader.flag(raw_human_review, human_review_path)
    if guidance and raw_human_review is None:
        reader.warnings.append(f"{human_review_path} is missing; treated as required.")
    target: Target = {
        "targetUid": reader.text(
            reader.field(item, FIELD_TARGET_UID), FIELD_TARGET_UID
        ),
        "status": reader.status(reader.field(item, FIELD_STATUS), FIELD_STATUS),
        "priority": reader.text(reader.field(item, FIELD_PRIORITY), FIELD_PRIORITY),
        "resource": resource,
        "resourceId": reader.text(
            reader.field(resource, FIELD_RESOURCE_ID),
            f"{FIELD_RESOURCE}.{FIELD_RESOURCE_ID}",
        )
        or "",
        "resourceAccountId": reader.text(
            reader.field(resource, FIELD_RESOURCE_ACCOUNT_ID),
            f"{FIELD_RESOURCE}.{FIELD_RESOURCE_ACCOUNT_ID}",
        )
        or "",
        "hasGuidance": bool(guidance),
        "guidance": guidance,
        "targetTypeName": reader.text(
            reader.field(guidance, FIELD_TARGET_TYPE_NAME), FIELD_TARGET_TYPE_NAME
        ),
        "metadata": metadata,
        "humanReviewRequired": human_review,
        "automationLevel": level.strip().lower() if level else None,
        "reversibility": reader.text(
            reader.field(metadata, FIELD_REVERSIBILITY), FIELD_REVERSIBILITY
        ),
        "resourceType": reader.text(
            reader.field(metadata, FIELD_RESOURCE_TYPE), FIELD_RESOURCE_TYPE
        ),
        "hasExamples": bool(reader.field(guidance, FIELD_EXAMPLES)),
        "steps": steps,
        "requiredPermissions": reader.names(
            reader.field(specification, FIELD_REQUIRED_PERMISSIONS),
            FIELD_REQUIRED_PERMISSIONS,
        ),
        "parameters": reader.records(
            reader.field(specification, FIELD_PARAMETERS), FIELD_PARAMETERS
        ),
        "expectedEndState": reader.text(
            reader.field(specification, FIELD_EXPECTED_END_STATE),
            FIELD_EXPECTED_END_STATE,
        ),
    }
    return target, reader.warnings


class GateResult(TypedDict):
    automatable: bool
    reasons: list[str]


class IamActions(TypedDict):
    actions: list[str]
    translated: dict[str, list[str]]
    implied: dict[str, list[str]]


class ReportStep(TypedDict):
    phase: StepPhase | None
    actions: list[str]
    description: str | None
    logic: str | None
    verifyAfter: str | None
    inverse: str | None


class InverseStep(TypedDict):
    forActions: list[str]
    calls: list[str]
    inverse: str


class RollbackContext(TypedDict):
    """What the guidance says about undoing the FIX, as input for a rollback-capable runbook."""

    candidate: bool
    reasons: list[str]
    reversibility: str | None
    inverseSteps: list[InverseStep]
    iamActions: list[str]
    warnings: list[str]


class ApiCall(TypedDict):
    service: str
    action: str


class GenerateRunbookGuidance(TypedDict):
    """The `guidance` input of `generate_runbook` (RemediationGuidanceInputSchema)."""

    apiCall: ApiCall
    requiredPermissions: list[str]
    resourceType: NotRequired[str]
    verifyAction: NotRequired[str]


class GuidanceReport(TypedDict):
    source: str
    targetUid: str | None
    targetTypeName: str | None
    resource: dict[str, Any]
    priority: str | None
    status: str | None
    metadata: dict[str, Any]
    gate: GateResult
    steps: list[ReportStep]
    parameters: list[dict[str, Any]]
    expectedEndState: str | None
    iamActions: IamActions
    generateRunbookGuidance: GenerateRunbookGuidance | None
    rollback: RollbackContext
    warnings: list[str]
    schemaWarnings: list[str]


# Identifiers called like functions in an Inverse ("PutBucketEncryption(Bucket=...)",
# "backup:DeleteBackupPlan(BackupPlanId=...)").
INVERSE_CALL = re.compile(r"\b(?:([a-z0-9-]+):)?([A-Z][A-Za-z0-9]+)\(")

# Deleting a whole data-bearing resource is never an acceptable rollback (generation-instructions
# Guardrails), even when the guidance's Inverse proposes it.
WHOLE_RESOURCE_DELETES = frozenset(
    {
        "s3:DeleteBucket",
        "dynamodb:DeleteTable",
        "rds:DeleteDBInstance",
        "rds:DeleteDBCluster",
        "ec2:TerminateInstances",
        "cloudformation:DeleteStack",
        "kms:ScheduleKeyDeletion",
        # Calls that destroy data or recovery points rather than configuration.
        "s3:DeleteObject",
        "s3:DeleteObjects",
        "dynamodb:DeleteBackup",
        "backup:DeleteRecoveryPoint",
        "backup:DeleteBackupVault",
        "rds:DeleteDBSnapshot",
        "rds:DeleteDBClusterSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeleteSnapshot",
    }
)

# Matched by action name as well, so an Inverse or FIX that omits or misnames its service
# cannot slip past the check.
WHOLE_RESOURCE_DELETE_NAMES = frozenset(
    call.split(":", 1)[1] for call in WHOLE_RESOURCE_DELETES
)
LEADING_VERB = re.compile(r"[A-Z][a-z]+")
NAME_WORDS = re.compile(r"[A-Z][a-z0-9]*")

# Reversibility values that allow a rollback; anything else (including none) fails closed.
REVERSIBLE_VALUES = frozenset({"fully reversible", "partially reversible"})


@functools.lru_cache(maxsize=None)
def _service_operations(service: str) -> frozenset[str] | None:
    """Operation names of one AWS service from botocore's bundled models, or None if unknown."""
    try:
        import botocore.session

        return frozenset(
            botocore.session.get_session().get_service_model(service).operation_names
        )
    except (
        Exception
    ):  # noqa: BLE001 - botocore missing or service unknown: fall back to the guidance
        return None


def split_actions(
    service_field: str | None,
    action_field: str | None,
    required_permissions: frozenset[str] = frozenset(),
) -> list[str]:
    """Expand a guidance step's comma-separated `Service` and `Action` into `service:Action`.

    A multi-service step lists services and actions as two independent lists
    ("dynamodb, backup" / "DescribeTable, ListBackupPlans, ListBackupSelections"), so their
    positions do not pair up. Each action is assigned to the listed service whose API actually
    has that operation (botocore models), then to the service the guidance's own
    RequiredPermissions names it under, and only then to the first listed service.
    """
    services = [
        s.strip().lower() for s in (service_field or "").split(",") if s.strip()
    ]
    actions = [a.strip() for a in (action_field or "").split(",") if a.strip()]
    resolved: list[str] = []
    unprefixed: list[str] = []
    for action in actions:
        if ":" in action:
            # Already "service:Action": keep its own service instead of prefixing it again.
            service, name = action.split(":", 1)
            resolved.append(f"{service.strip().lower()}:{name.strip()}")
        else:
            unprefixed.append(action)
    if not services or not unprefixed:
        return resolved
    if len(services) == 1:
        return resolved + [f"{services[0]}:{action}" for action in unprefixed]
    operations = {service: _service_operations(service) for service in services}
    for action in unprefixed:
        owner = next(
            (s for s in services if action in (operations[s] or frozenset())), None
        )
        owner = owner or next(
            (s for s in services if f"{s}:{action}" in required_permissions),
            services[0],
        )
        resolved.append(f"{owner}:{action}")
    return resolved


def translate_iam_actions(names: list[str]) -> IamActions:
    actions: list[str] = []
    translated: dict[str, list[str]] = {}
    implied: dict[str, list[str]] = {}
    for name in names:
        targets = API_TO_IAM_ACTIONS.get(name)
        if targets:
            translated[name] = list(targets)
        for action in targets or (name,):
            if action not in actions:
                actions.append(action)
    for name, extras in IMPLIED_ACTIONS.items():
        missing = [
            extra for extra in extras if name in actions and extra not in actions
        ]
        if missing:
            implied[name] = missing
            actions.extend(missing)
    return {"actions": sorted(actions), "translated": translated, "implied": implied}


def evaluate_gate(
    target: Target, fix_actions: list[str], fix_action_names: list[str]
) -> GateResult:
    """Decide whether the guidance may become an automated runbook. Fails closed.

    `fix_action_names` are the FIX steps' raw action names, so a replacement is caught even when a
    step omits its `Service` and no `service:Action` could be built for it.
    """
    reasons: list[str] = []
    has_guidance = target["hasGuidance"]
    if not has_guidance:
        reasons.append(
            "The remediation target carries no guidance; call with ShowGuidance=true."
        )
    if target["humanReviewRequired"] is True:
        reasons.append(
            "Guidance sets HumanReviewRequired: a person must decide this remediation."
        )
    elif has_guidance and target["humanReviewRequired"] is None:
        reasons.append(
            "Guidance HumanReviewRequired is missing or cannot be read; treating it as required."
        )
    level = target["automationLevel"]
    if has_guidance and level != FULL_AUTOMATION:
        reasons.append(f"Guidance AutomationLevel is {level!r}, not 'full'.")
    if target["status"] == RESOLVED_STATUS:
        reasons.append("The remediation target is already Resolved.")
    if has_guidance and not fix_actions:
        reasons.append(
            "No FIX step names an API action (Service and Action); the guidance cannot be automated as is."
        )
    kinds = {
        name: fix_change_kind(name, target["resourceType"])
        for name in _distinct_fix_names(fix_actions, fix_action_names)
    }

    def names_of(kind: FixChangeKind) -> str:
        return ", ".join(sorted(name for name, found in kinds.items() if found == kind))

    if names_of("replacement"):
        reasons.append(
            f"The FIX creates a replacement resource ({names_of('replacement')}) instead of "
            "changing the resource in the finding, which would stay non-compliant."
        )
    if names_of("destructive"):
        reasons.append(
            "The FIX deletes the resource in the finding or deletes or overwrites its data "
            f"({names_of('destructive')})."
        )
    if names_of("other-resource"):
        reasons.append(
            f"The FIX changes a resource of another service ({names_of('other-resource')}), "
            "not the resource in the finding."
        )
    writes = non_fix_writes(target["steps"])
    if writes:
        reasons.append(
            "A step other than FIX calls something that is not a read ("
            + ", ".join(writes)
            + "); only FIX steps may change resources."
        )
    if names_of("unrecognized"):
        reasons.append(
            f"The FIX calls {names_of('unrecognized')}, which is not a verb known to change the "
            "resource in place; the gate refuses verbs it does not recognize."
        )
    return {"automatable": not reasons, "reasons": reasons}


FixChangeKind = Literal[
    "in-place", "replacement", "destructive", "other-resource", "unrecognized"
]


def fix_change_kind(name: str, resource_type: str | None) -> FixChangeKind:
    """Whether a FIX action changes the finding's resource in place, judged by its API verb.

    `Create` and `Delete` are compared with the finding's `ResourceType`, ignoring case,
    separators and a plural ending, so `AWS::EC2::VPC` and `AwsEc2Vpc` both name a VPC. Naming the
    resource's own type is a replacement (CreateBucket) or destructive (DeleteBucket,
    DeleteVpcEndpoints on a VPC endpoint). Naming a part of it passes (CreateBucketPolicy for a
    bucket), and so does a call on SAFE_CREATE_DELETE_ACTIONS. Anything else, including a parent
    resource (DeleteVpc on a subnet), is unrecognized and refused. A call on another service than
    the finding's (iam:PutRolePolicy on a bucket) is refused unless it is on that list. Without a
    ResourceType there is nothing to compare, so the call is unrecognized. A Create or Start that
    names a restore, copy, replica or import is a replacement; a Delete that names data (a backup,
    snapshot, object, version, volume or image) and an in-place call that writes data (PutObject,
    UpdateItem) are destructive.
    """
    action = _action_name(name)
    verb = _leading_verb(action)
    name_words = NAME_WORDS.findall(action[len(verb) :])
    words = set(name_words)
    if verb in ("Start", CREATE_VERB) and words & REPLACEMENT_WORDS:
        return "replacement"
    if verb in REPLACEMENT_VERBS:
        return "replacement"
    if verb == DELETE_VERB and (
        action in WHOLE_RESOURCE_DELETE_NAMES or words & DATA_WORDS
    ):
        return "destructive"
    if verb in IN_PLACE_VERBS and name_words and name_words[-1] in DATA_WRITE_WORDS:
        return "destructive"
    if verb not in IN_PLACE_VERBS | {CREATE_VERB, DELETE_VERB}:
        return "unrecognized"
    resource_key = re.sub(r"[^a-z0-9]", "", (resource_type or "").lower())
    if not resource_key:
        return "unrecognized"
    target = action[len(verb) :].lower()
    nouns = _resource_nouns(resource_type)
    if verb in (CREATE_VERB, DELETE_VERB) and _names_own_type(
        target, resource_key, nouns
    ):
        return "replacement" if verb == CREATE_VERB else "destructive"
    if _service_action(name, action) in SAFE_CREATE_DELETE_ACTIONS:
        return "in-place"
    if not _same_service(name, resource_type):
        return "other-resource"
    if verb in IN_PLACE_VERBS:
        return "in-place"
    if nouns and nouns[0] and target.startswith(nouns[0]):
        return "in-place"
    return "unrecognized"


def deletes_finding_resource(name: str, resource_type: str | None) -> bool:
    """Whether a call deletes the finding's own resource type, singular or plural. A rollback
    may delete what its remediation created (a backup plan), but never the finding's resource.
    """
    action = _action_name(name)
    resource_key = re.sub(r"[^a-z0-9]", "", (resource_type or "").lower())
    return (
        _leading_verb(action) == DELETE_VERB
        and bool(resource_key)
        and _names_own_type(
            action[len(DELETE_VERB) :].lower(),
            resource_key,
            _resource_nouns(resource_type),
        )
    )


def _same_service(name: str, resource_type: str | None) -> bool:
    """Whether the call's service is the finding's: `s3:` for `AWS::S3::Bucket` or `AwsS3Bucket`.
    The service is matched at the start of the type's service part, so `es:` does not match
    `AwsSesConfigurationSet`. A call without a service, or a service the type does not name,
    fails closed."""
    service = name.split(":", 1)[0] if ":" in name else ""
    service_key = re.sub(r"[^a-z0-9]", "", service.split("-")[0].lower())
    if not service_key:
        return False
    value = resource_type or ""
    if "::" in value:
        type_service = value.split("::")[1] if value.count("::") >= 2 else ""
    else:
        type_service = value.removeprefix("Aws")
    type_key = re.sub(r"[^a-z0-9]", "", type_service.lower())
    keys = (service_key, *SERVICE_TYPE_NAMES.get(service_key, ()))
    return bool(type_key) and any(type_key.startswith(key) for key in keys)


def _names_own_type(target: str, resource_key: str, nouns: list[str]) -> bool:
    """Whether a Create/Delete names the finding's own type, singular or plural
    (DeleteVpcEndpoints on AWS::EC2::VPCEndpoint, CreateDefaultVpc on AWS::EC2::VPC)."""
    forms = {target, target.removesuffix("s"), target.removesuffix("es")}
    return any(
        resource_key.endswith(form)
        or any(noun and form.endswith(noun) for noun in nouns)
        for form in forms
        if form
    )


def _resource_nouns(resource_type: str | None) -> list[str]:
    """The resource's own noun, lowercased, longest first. `AWS::S3::Bucket` gives `bucket`. An ASFF
    type such as `AwsEc2SecurityGroup` does not mark where the service ends, so each run of
    trailing words is a candidate: `securitygroup`, `group`."""
    value = resource_type or ""
    if "::" in value:
        return [re.sub(r"[^a-z0-9]", "", value.split("::")[-1].lower())]
    words = [word.lower() for word in NAME_WORDS.findall(value)][2:]
    return ["".join(words[start:]) for start in range(len(words))]


def _service_action(name: str, action: str) -> str:
    service = name.split(":", 1)[0].strip().lower() if ":" in name else ""
    return f"{service}:{action}"


def _action_name(name: str) -> str:
    """The API name without its service and without spaces or punctuation, so `Create Bucket`
    or `CreateBucket()` is judged as CreateBucket."""
    return re.sub(r"[^A-Za-z0-9]", "", name.split(":")[-1])


def _leading_verb(action: str) -> str:
    match = LEADING_VERB.match(action)
    return match.group(0) if match else ""


def non_fix_writes(steps: list[TargetStep]) -> list[str]:
    """Calls in steps other than FIX whose verb is not a read."""
    writes: list[str] = []
    for step in steps:
        if step["phase"] == "FIX":
            continue
        for name in (part.strip() for part in step["action"].split(",")):
            if name and _leading_verb(_action_name(name)) not in READ_VERBS:
                writes.append(f"{step['phase'] or 'unknown phase'}: {name}")
    return list(dict.fromkeys(writes))


def _distinct_fix_names(
    fix_actions: list[str], fix_action_names: list[str]
) -> list[str]:
    """The FIX `service:Action` names, plus any raw action name no `service:Action` covers."""
    covered = {action.split(":")[-1] for action in fix_actions}
    raw = [name for name in fix_action_names if name.split(":")[-1] not in covered]
    return list(dict.fromkeys(fix_actions + raw))


def collect_warnings(target: Target) -> list[str]:
    # default=str: boto3 returns datetime objects (UpdatedAt, GeneratedAt) where a saved JSON
    # response has strings, so a scan that only ever saw fixtures would crash on a live call.
    text = json.dumps(target["guidance"], default=str)
    warnings: list[str] = []
    resource_id = target["resourceId"]
    identifiers = {resource_id, resource_id.split(":::")[-1].split("/")[-1]}
    if any(
        identifier and len(identifier) > 3 and identifier in text
        for identifier in identifiers
    ):
        warnings.append(
            "Step Logic names this target's resource. Derive the resource from the Finding "
            "parameter instead of copying the identifier into the runbook."
        )
    account_id = target["resourceAccountId"]
    if account_id and account_id in text:
        warnings.append(
            "Guidance text contains the account ID. Never hardcode it in the runbook."
        )
    for marker, note in CONSOLE_ONLY_DEFAULTS.items():
        if marker in text:
            warnings.append(
                f"Guidance defaults to a resource that may not exist: {note}. Check it before use."
            )
    if re.search(r"cron\(0 0/\$\{\w+\}", text):
        warnings.append(
            "The schedule template cron(0 0/${hours} ...) is invalid for 24 hours (AWS Backup rejects an "
            "increment of 24). Map daily to a fixed hour."
        )
    if target["hasExamples"]:
        warnings.append(
            "Examples are reference only. Do not paste them: they hardcode the target and may not handle "
            "the guidance's own defaults (for example KmsKeyId='aws/s3', which S3 stores verbatim and then "
            "fails every upload)."
        )
    return warnings


def _resolve_inverse_call(
    service: str, action: str, candidate_services: list[str]
) -> str:
    """`service:Action` for one Inverse call.

    An unprefixed call goes to the first candidate service whose API has that operation (the FIX
    step's own services first, then every other service the guidance uses), and only then to the
    FIX step's first service.
    """
    if service:
        return f"{service.lower()}:{action}"
    owner = next(
        (
            s
            for s in candidate_services
            if action in (_service_operations(s) or frozenset())
        ),
        None,
    )
    return f"{owner or (candidate_services[0] if candidate_services else '')}:{action}"


def build_rollback_context(
    target: Target, steps: list[ReportStep], gate: GateResult
) -> RollbackContext:
    """Extract the FIX steps' Inverse into rollback authoring input.

    A Custom Runbook's rollback runs only when its document is started directly with
    Rollback=ROLLBACK; the Web UI / MCP one-click rollback covers a fixed set of built-in
    controls. The rollback is still worth authoring when the change is reversible, because
    it is the tested way back.
    """
    reversibility = target["reversibility"]
    inverse_steps: list[InverseStep] = []
    calls: list[str] = []
    guidance_services = list(
        dict.fromkeys(
            action.split(":", 1)[0] for step in steps for action in step["actions"]
        )
    )
    for step in steps:
        inverse = step["inverse"]
        if step["phase"] != "FIX" or not inverse:
            continue
        step_services = list(
            dict.fromkeys(action.split(":", 1)[0] for action in step["actions"])
        )
        candidate_services = step_services + [
            s for s in guidance_services if s not in step_services
        ]
        step_calls: list[str] = []
        for service, action in INVERSE_CALL.findall(inverse):
            call = _resolve_inverse_call(service, action, candidate_services)
            if call not in step_calls:
                step_calls.append(call)
        inverse_steps.append(
            {"forActions": step["actions"], "calls": step_calls, "inverse": inverse}
        )
        calls.extend(step_calls)

    reasons: list[str] = []
    if not gate["automatable"]:
        reasons.append(
            "The remediation itself is refused by the gate, so there is nothing to roll back."
        )
    if (reversibility or "").strip().lower() not in REVERSIBLE_VALUES:
        reasons.append(
            f"Guidance Reversibility is {reversibility!r}: the original state cannot be restored."
        )
    if not inverse_steps:
        reasons.append("No FIX step carries an Inverse to restore from.")
    destructive = sorted(
        {
            call
            for call in calls
            if call.split(":")[-1] in WHOLE_RESOURCE_DELETE_NAMES
            or deletes_finding_resource(call, target["resourceType"])
        }
    )
    if destructive:
        reasons.append(
            "The Inverse deletes a whole resource ("
            + ", ".join(destructive)
            + "), which a rollback must never do."
        )

    warnings: list[str] = []
    text = " ".join(step["inverse"] for step in inverse_steps)
    if "DeleteBackupPlan" in text:
        warnings.append(
            "The Inverse deletes the backup plan, but AWS Backup rejects DeleteBackupPlan while selections "
            "exist, and a shared plan may hold other resources' selections. Delete only the selection this "
            "run created, then the plan only if this run created it and it is now empty."
        )
    if re.search(r"Delete\w+\(", text):
        warnings.append(
            "The Inverse deletes something. Record exactly what the remediation created in the snapshot and "
            "delete only that, so a rollback never removes coverage or configuration it did not add."
        )
    if "Suspended" in text or "cannot" in text.lower():
        warnings.append(
            "The Inverse restores only a partial state; say so in rollbackDescription."
        )

    candidate = not reasons
    iam = translate_iam_actions(calls)["actions"] if candidate else []
    return {
        "candidate": candidate,
        "reasons": reasons,
        "reversibility": reversibility,
        "inverseSteps": inverse_steps,
        "iamActions": iam,
        "warnings": warnings,
    }


def build_report(response: Any) -> GuidanceReport:
    target, schema_warnings = read_target(response)

    steps: list[ReportStep] = []
    fix_actions: list[str] = []
    fix_action_names: list[str] = []
    verify_actions: list[str] = []
    required_permissions = frozenset(target["requiredPermissions"])
    for step in target["steps"]:
        step_actions = split_actions(
            step["service"], step["action"], required_permissions
        )
        if step["phase"] == "FIX":
            fix_actions.extend(step_actions)
            fix_action_names.extend(
                a.strip() for a in step["action"].split(",") if a.strip()
            )
        if step["phase"] == "VERIFY":
            verify_actions.extend(step_actions)
        steps.append(
            {
                "phase": step["phase"],
                "actions": step_actions,
                "description": step["description"],
                "logic": step["logic"],
                "verifyAfter": step["verifyAfter"],
                "inverse": step["inverse"],
            }
        )

    step_actions_all = [action for step in steps for action in step["actions"]]
    iam = translate_iam_actions(target["requiredPermissions"] + step_actions_all)
    gate = evaluate_gate(target, fix_actions, fix_action_names)

    runbook_guidance: GenerateRunbookGuidance | None = None
    if gate["automatable"] and fix_actions:
        service, action = fix_actions[0].split(":", 1)
        runbook_guidance = {
            "apiCall": {"service": service, "action": action},
            "requiredPermissions": iam["actions"],
        }
        if target["resourceType"]:
            runbook_guidance["resourceType"] = target["resourceType"]
        if verify_actions:
            runbook_guidance["verifyAction"] = verify_actions[0].split(":", 1)[1]

    return {
        "source": "securityhub:GetRemediationsV2",
        "targetUid": target["targetUid"],
        "targetTypeName": target["targetTypeName"],
        "resource": target["resource"],
        "priority": target["priority"],
        "status": target["status"],
        "metadata": target["metadata"],
        "gate": gate,
        "steps": steps,
        "parameters": target["parameters"],
        "expectedEndState": target["expectedEndState"],
        "iamActions": iam,
        "generateRunbookGuidance": runbook_guidance,
        "rollback": build_rollback_context(target, steps, gate),
        "warnings": collect_warnings(target),
        "schemaWarnings": schema_warnings,
    }


def fetch(
    *, target_uid: str | None, metadata_uid: str | None, region: str | None
) -> dict[str, Any]:
    try:
        import boto3
    except ImportError:  # pragma: no cover
        raise RuntimeError("requires boto3 (pip install boto3)") from None
    client = boto3.client("securityhub", region_name=region)
    if not hasattr(client, "get_remediations_v2"):
        raise RuntimeError("this boto3 has no get_remediations_v2; upgrade boto3")
    request: dict[str, Any] = {"ShowGuidance": True}
    if target_uid:
        request["TargetUid"] = target_uid
    else:
        request["MetadataUid"] = metadata_uid
    response: dict[str, Any] = client.get_remediations_v2(**request)
    response.pop("ResponseMetadata", None)
    return response


class JsonErrorArgumentParser(argparse.ArgumentParser):
    """Reports usage errors as the same one-line JSON error (exit 2) as every other failure."""

    def error(self, message: str) -> NoReturn:
        print(json.dumps({"error": f"UsageError: {message}"}))
        sys.exit(EXIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    parser = JsonErrorArgumentParser(
        description="Read Security Hub remediation plan guidance and turn it into runbook authoring input."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--target-uid")
    source.add_argument("--metadata-uid", help="metadata.uid of an exposure finding")
    source.add_argument("--input-file", help="saved GetRemediationsV2 JSON response")
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
    )
    args = parser.parse_args(argv)
    try:
        if args.input_file:
            with open(args.input_file, encoding="utf-8") as handle:
                response = json.load(handle)
        else:
            response = fetch(
                target_uid=args.target_uid,
                metadata_uid=args.metadata_uid,
                region=args.region,
            )
        report = build_report(response)
    except (
        Exception
    ) as error:  # noqa: BLE001 - every failure is reported as one JSON error
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}))
        return EXIT_ERROR
    print(json.dumps(report, indent=2, default=str))
    return EXIT_AUTOMATABLE if report["gate"]["automatable"] else EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
