#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Validate an SSM Automation runbook (schema 0.3) against ASR rules.

Deterministic: same input -> same verdict.

Usage:
    validate_runbook.py <runbook.yaml> [--lenient] [--mode custom|builtin]

`--mode` selects which rules apply (not their severity). `custom`, the default,
additionally enforces the Orchestrator's two-parameter contract; `builtin` exempts
it, because a built-in remediation is a child document behind a wrapper that has
already parsed the finding.

Findings come in three severities:

- **hard** — always an error. Shape and security rules that cannot be argued with.
- **advisory** — an error by default; `--lenient` downgrades it to a warning.
- **hint** — always a warning, in both modes. For rules that *infer* a problem
  rather than recognise one, so a false positive costs the author a sentence to
  read instead of a blocked run. `[destructive-verb]` is the reason this tier
  exists: it guesses from an API's name, and the guess is wrong for three APIs
  this solution already ships.

Exit codes: 0 = valid, 1 = findings (invalid), 2 = usage/parse error.
Prints a JSON report ({valid, errors, warnings, schemaVersion}) to stdout.
`valid` tracks `errors` only, so a hint never fails a run.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from typing import Any, Literal, TypedDict

# Which kind of runbook is being validated. A `Literal` rather than a bare `str`
# so a caller passing "builtins" is a type error here instead of silently
# selecting the stricter mode and reporting rules it meant to opt out of.
RunbookMode = Literal["custom", "builtin"]

try:
    # PyYAML ships no inline types and mypy will not silence a stub package that
    # exists on PyPI, so the alternative to this ignore is adding types-PyYAML to
    # the solution's dev group — a lock-file entry on the `poetry export` path in
    # build-s3-dist.sh, for a directory the build does not package. `safe_load`
    # is typed `Any` in the stubs anyway, so the ignore costs no real precision.
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    print("validate_runbook: requires PyYAML (pip install pyyaml)", file=sys.stderr)
    raise SystemExit(2)

# Matched exactly, because these four are destructive whatever the context, and an
# exact match is what earns a *blocking* finding. The general "does this look
# destructive?" question is answered by DESTRUCTIVE_VERB_PATTERN below, at a
# severity that suits a guess.
DANGEROUS_APIS = ["DeleteBucket", "TerminateInstances", "DeleteStack", "DeleteTable"]

# Calls that switch a security control off. Curated and exact-matched for the
# reason above plus one more: this rule's message says "prohibited", so an entry
# has to be indefensible in *every* remediation. Two failed that test and were
# removed — `RemovePermission`, because resource policies only ever grant, so
# removing a statement revokes access rather than disabling a control (the shipped
# Lambda.1 remediation exists to do exactly that), and `PutBucketAcl`, which moved
# to DISCOURAGED_APIS below.
DISABLE_SECURITY_APIS = [
    "DisableEncryption",
    "SuspendLogging",
    "DeleteTrail",
    "StopLogging",
    "DisableKey",
    "DeleteAlarm",
    "DisableAlarmActions",
    "DeletePolicy",
]

# API -> why to reach for something else. These are legitimate calls that are the
# wrong tool for the job in an ASR remediation, which is a weaker claim than
# DISABLE_SECURITY_APIS makes, so they carry their own message and their own
# reason rather than being labelled prohibited.
DISCOURAGED_APIS = {
    "PutBucketAcl": (
        "manage bucket access with a bucket policy and Block Public Access — ACLs "
        "are disabled by default on new buckets. Granting the S3 LogDelivery group "
        "write access to a logging bucket is the accepted exception"
    ),
}

# The general rule the three exact-match lists above cannot be: any API whose verb
# suggests it takes something away. Curated lists only catch what someone thought
# to add, so a novel `DeleteSomething` sails past all three.
#
# It is a hint, never an error, and that is the whole design. The verb cannot
# decide the question — the *object* can. `DeleteBucket` destroys a resource;
# `DeleteBucketPolicy` removes bad configuration. Auditing the 44 distinct
# `inputs.Api` values in this solution's shipped runbooks, this pattern matches
# three, and all three are correct as written. So the rule is right about the
# category and wrong about roughly one API in fifteen — which is useful as a
# prompt to justify the call, and unacceptable as a gate.
DESTRUCTIVE_VERB_PATTERN = re.compile(
    r"^(Delete|Terminate|Disable|Suspend|Stop|Remove|Revoke|Detach|Deregister)"
)

# API -> why taking this thing away is the remediation rather than a regression.
# Suppresses the hint only; these stay eligible for the exact-match rules, so
# adding one here cannot smuggle an API past `dangerous-api`.
#
# The first three are `inputs.Api` matches. The rest may appear in
# `aws:executeScript` bodies and remain legitimate if moved to an
# `aws:executeAwsApi` step.
LEGITIMATE_DESTRUCTIVE_APIS = {
    "DeleteDBSnapshot": "EncryptRDSSnapshot deletes the unencrypted original",
    "DeleteDBClusterSnapshot": "EncryptRDSSnapshot, cluster variant",
    "DeleteLaunchConfiguration": "replaced by a compliant copy, then removed",
    "DeleteLoginProfile": "RevokeUnusedIAMUserCredentials removes a stale password",
    "DeleteAccessKey": "removing an unused key is the fix, not a loss of function",
    "DeleteBucketPolicy": "removes a permissive policy",
    "DeleteSecret": "removes an exposed secret",
    "RemovePermission": "a resource policy only grants, so removing revokes",
    "RevokeSecurityGroupIngress": "closing an open rule is the canonical remediation",
    "RevokeSecurityGroupEgress": "as above, egress side",
}

# Category 2: credential exposure (matched case-insensitively).
CREDENTIAL_EXPOSURE_COMMANDS = [
    "net user",
    "runas",
    "cmdkey",
    "useradd",
    "passwd",
    "mysql -p",
]

# Category 8: insecure transport. NO_VERIFY_FLAG split to avoid scanner false positives.
_NO_VERIFY_FLAG = "--no-verify" + "-ssl"
INSECURE_PATTERNS = [
    re.compile(re.escape(_NO_VERIFY_FLAG)),
    re.compile(r"PYTHONHTTPSVERIFY\s*=\s*0"),
    re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0"),
    re.compile(r"curl\s+.*-k\b"),
]

ACCOUNT_ID_PATTERN = re.compile(r"\b\d{12}\b")
ACCESS_KEY_PATTERN = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")

# A secret must be *assigned* a value. Matching the bare identifier flags runbooks
# that legitimately name it, e.g. ReplaceCodeBuildClearTextCredentials searching for
# "AWS_SECRET_ACCESS_KEY". Any key ending in "password" counts (MasterUserPassword,
# db_password), so the value decides — see SECRET_VALUE_ALLOWED.
# The value is matched in all three forms a runbook writes it, not just quoted:
# `MasterUserPassword: hunter2` in YAML and `password=hunter2` in a shell body are
# the unquoted forms, and matching only quotes let both past a hard rule.
#
# The gap between key and value is `[ \t]*`, not `\s*`: a newline there means the
# key opens a nested mapping (`Password:` then `type: String`), and the value it
# would otherwise reach for belongs to a different key. Braces stay out of the
# unquoted branch so an unquoted `{{ Parameter }}` matches as an empty value and
# is exempted below rather than read as a literal.
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(aws_secret_access_key|secret_access_key|password|passwd)[ \t]*[:=][ \t]*"
    r"""(?:"([^"]*)"|'([^']*)'|([^\s'"#,{}]*))""",
    re.IGNORECASE,
)
# Values that cannot be a literal secret: SSM/CFN template references, booleans,
# numbers, empty. This is what keeps IAM password-*policy* runbooks valid
# (AllowUsersToChangePassword: "True", MinimumPasswordLength: "14").
SECRET_VALUE_ALLOWED = re.compile(
    r"^\s*(\{\{.*\}\}|true|false|null|none|\d+|)\s*$", re.IGNORECASE
)
# An unquoted value that reads the secret from somewhere instead of spelling it
# out: an environment lookup, an event field, an attribute, a call, a shell
# variable (`password=$DB_PASS`, `password = os.environ["X"]`, `event["Pw"]`).
# Only the unquoted branch consults this — inside quotes those same characters are
# part of a literal, so `password: "$DB_PASS"` stays a finding as it always was.
SECRET_VALUE_IS_INDIRECT = re.compile(r"[$(.\[]")

# Wildcards only count as privilege escalation when they are the value of an
# Action/NotAction key. Bare `"*"` is legitimate elsewhere: "Principal": "*" is
# required by an SSL-deny bucket policy, and "Resource": "*" is often unavoidable.
WILDCARD_ACTION_PATTERN = re.compile(
    r"""["'](?:Not)?Action["']\s*:\s*"""
    r"""(?:["']\*(?::\*)?["']|\[[^\]]*?["']\*(?::\*)?["'][^\]]*?\])""",
    re.IGNORECASE | re.DOTALL,
)
ADMIN_POLICY_PATTERN = re.compile(
    r"""["']AdministratorAccess["']|arn:aws[\w-]*:iam::aws:policy/AdministratorAccess"""
)
# A wildcard Action under "Effect": "Deny" *removes* privilege, so it is the
# opposite of escalation — PutS3BucketPolicyDeny and the TLS-only bucket policies
# are built exactly that way. Effect is matched within the enclosing statement
# object, not the whole script, so one Deny cannot excuse an Allow elsewhere.
DENY_EFFECT_PATTERN = re.compile(
    r"""["']Effect["']\s*:\s*["']Deny["']""", re.IGNORECASE
)


def enclosing_statement(text: str, start: int, end: int) -> str:
    """The `{...}` object containing `text[start:end]`, or `text` if unbalanced.

    Brace-walks outward so an Effect/Action pair is only ever read from the same
    policy statement. Falling back to the whole script on unbalanced braces keeps
    the rule fail-closed: an unparseable policy still gets flagged.
    """
    depth = 0
    left = start
    while left > 0:
        left -= 1
        if text[left] == "}":
            depth += 1
        elif text[left] == "{":
            if depth == 0:
                break
            depth -= 1
    else:
        return text

    depth = 0
    right = end
    while right < len(text):
        if text[right] == "{":
            depth += 1
        elif text[right] == "}":
            if depth == 0:
                return text[left : right + 1]
            depth -= 1
        right += 1
    return text


def escalating_wildcard_actions(script: str) -> bool:
    """True when a wildcard Action appears in a statement that is not a Deny."""
    return any(
        not DENY_EFFECT_PATTERN.search(
            enclosing_statement(script, match.start(), match.end())
        )
        for match in WILDCARD_ACTION_PATTERN.finditer(script)
    )


def script_bodies(doc: dict[str, Any]) -> list[str]:
    """Every `aws:executeScript` body in the document, read off the parsed YAML.

    Reading the parsed document rather than the raw text is what makes this
    serialization-agnostic. Hand-written runbooks use a block scalar
    (`Script: |`), but `ssm:GetDocument` returns the same body as a
    double-quoted scalar with escaped newlines, which no `Script:\\s*\\|` regex
    can match. YAML normalizes both to one Python string.
    """
    bodies = []
    for step in doc.get("mainSteps") or []:
        if not isinstance(step, dict):
            continue
        inputs = step.get("inputs")
        if not isinstance(inputs, dict):
            continue
        script = inputs.get("Script")
        if isinstance(script, str):
            bodies.append(script)
    return bodies


class ValidationResult(TypedDict):
    """The report `validate` returns, and the CLI prints as JSON.

    Spelled out because every caller indexes it by key — the test suite asserts
    on `errors` entries, and `main` branches on `valid`. `schemaVersion` is
    `None` when the document could not be parsed far enough to read one.
    """

    valid: bool
    errors: list[str]
    warnings: list[str]
    schemaVersion: str | None


class Findings:
    """Where the rules file what they find, at the severity the module docstring sets.

    Handed to every rule check so a rule declares its severity by which method it
    calls, rather than by which list it appends to. `strict` lives here for the
    same reason: one place decides what `--lenient` changes.
    """

    def __init__(self, strict: bool) -> None:
        self.strict = strict
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, msg: str) -> None:
        """Hard: an error in both modes."""
        self.errors.append(msg)

    def advisory(self, msg: str) -> None:
        """An error by default; `--lenient` downgrades it to a warning."""
        (self.errors if self.strict else self.warnings).append(msg)

    def hint(self, msg: str) -> None:
        """A warning in both modes, deliberately not affected by `strict`.

        A rule that infers a problem from a name must not be able to fail a run,
        or the author's only escape is `--lenient`, which would also silence the
        rules that are certain.
        """
        self.warnings.append(msg)


# One entry of `mainSteps`, as it comes out of the parser.
#
# `Mapping[str, object]` rather than the `dict[str, Any]` the step rules shared with
# everything else, and rather than a `TypedDict` naming the fields they read
# (`name`, `action`, `inputs`, `timeoutSeconds`): a step arrives straight from
# `yaml.safe_load`, so a `TypedDict` declaring `name: str` would assert exactly the
# validity this module exists to doubt — nothing has checked that `name` is present,
# let alone a string, by the time a rule reads it. `object` values keep the
# annotation true and oblige each rule to establish the type it needs, which is what
# the `isinstance` checks in these rules already do.
AutomationStep = Mapping[str, object]


def _step_name(step: AutomationStep) -> str:
    """The step's name for a message, or "(unnamed)" when it has no usable one.

    `isinstance` rather than a bare `or` keeps malformed numeric names reportable
    without claiming that unchecked input is already a string.
    """
    name = step.get("name")
    return name if isinstance(name, str) and name else "(unnamed)"


def _check_schema_version(doc: dict[str, Any], findings: Findings) -> str | None:
    """Returns the version found, which the report echoes even when it is wrong."""
    schema_version: str | None = (
        doc.get("schemaVersion") if isinstance(doc.get("schemaVersion"), str) else None
    )
    if not schema_version:
        findings.error(
            '[schema-version] Missing required field: schemaVersion (expected "0.3").'
        )
    elif schema_version != "0.3":
        findings.error(
            f'[schema-version] Unsupported schemaVersion "{schema_version}" — ASR runbooks must use "0.3".'
        )
    return schema_version


def _check_assume_role(doc: dict[str, Any], findings: Findings) -> None:
    assume_role = doc.get("assumeRole")
    if not isinstance(assume_role, str) or "AutomationAssumeRole" not in assume_role:
        findings.error(
            '[assume-role] assumeRole must be a string containing "AutomationAssumeRole". '
            'Expected: "{{ AutomationAssumeRole }}".'
        )


def _check_automation_role_param(doc: dict[str, Any], findings: Findings) -> None:
    params = doc.get("parameters")
    if not isinstance(params, dict):
        findings.error("[automation-role-param] Missing required section: parameters.")
    elif not params.get("AutomationAssumeRole"):
        findings.error(
            "[automation-role-param] parameters.AutomationAssumeRole is required by ASR runbooks."
        )


# The parameters the ASR Orchestrator supplies when it starts a Custom Runbook.
# `Orchestrator/exec_ssm_doc.py` builds exactly these two (plus the optional
# `Detail.docParameters` merge, which an author cannot rely on), so a required
# parameter outside this set makes StartAutomationExecution fail with
# `InvalidAutomationExecutionParametersException` before the first step runs.
ORCHESTRATOR_SUPPLIED_PARAMETERS = frozenset({"AutomationAssumeRole", "Finding"})


def _check_orchestrator_parameter_contract(
    doc: dict[str, Any], findings: Findings
) -> None:
    """Custom Runbooks only: the document must start from the two parameters sent.

    Scoped by mode rather than by severity because the distinction is
    applicability, not confidence. A built-in remediation is a *child* document
    invoked behind a wrapper that has already parsed the finding, which is why the
    built-ins legitimately take `BucketName`/`TopicArn`; for those the rule is not
    a weaker warning, it simply does not apply.

    Shape only, in the same sense as `[automation-role-param]`: this cannot prove
    the runbook *reads* `Finding`, only that an execution carrying nothing but the
    Orchestrator's two parameters would start. A runbook that declares `Finding`
    and ignores it still fails at run time, just not here.
    """
    params = doc.get("parameters")
    if not isinstance(params, dict):
        # [automation-role-param] has already reported the missing section; a
        # second message about the same absence would only add noise.
        return
    if "Finding" not in params:
        findings.error(
            "[orchestrator-parameters] parameters.Finding is required: the "
            "Orchestrator passes only Finding and AutomationAssumeRole, so every "
            "resource identifier has to be derived from the finding."
        )
    for name, spec in params.items():
        if name in ORCHESTRATOR_SUPPLIED_PARAMETERS:
            continue
        if not isinstance(spec, dict) or "default" not in spec:
            findings.error(
                f"[orchestrator-parameters] parameters.{name} is required, but the "
                "Orchestrator never sends it. Give it a default, or derive the "
                "value from Finding instead of taking it as a parameter."
            )


def _check_hardcoded_secrets(raw: str, findings: Findings) -> None:
    """Reads the raw YAML, not the parsed document: a secret is a literal in the text."""
    if ACCOUNT_ID_PATTERN.search(raw):
        findings.advisory(
            "[hardcoded-secret] YAML contains what appears to be a hardcoded AWS account ID. "
            "Use parameters instead."
        )
    if ACCESS_KEY_PATTERN.search(raw):
        findings.error(
            "[hardcoded-secret] YAML contains what appears to be an AWS access key. "
            "Never embed credentials in runbooks."
        )
    for match in SECRET_ASSIGNMENT_PATTERN.finditer(raw):
        double_quoted, single_quoted, unquoted = (
            match.group(2),
            match.group(3),
            match.group(4),
        )
        # Exactly one of the three alternatives matched; the unquoted one can be
        # empty (`Password:` opening a nested mapping), which reads as allowed.
        value: str = next(
            v for v in (double_quoted, single_quoted, unquoted) if v is not None
        )
        if SECRET_VALUE_ALLOWED.match(value):
            continue
        if unquoted is not None and SECRET_VALUE_IS_INDIRECT.search(unquoted):
            continue
        findings.error(
            "[hardcoded-secret] YAML contains what appears to be a hardcoded secret or password."
        )
        break


def _check_privilege_escalation(doc: dict[str, Any], findings: Findings) -> None:
    """Wildcard IAM and AdministratorAccess inside `aws:executeScript` bodies."""
    for script in script_bodies(doc):
        if escalating_wildcard_actions(script):
            findings.error(
                "[privilege-escalation] Script grants a wildcard IAM action. "
                "Use scoped permissions."
            )
        if ADMIN_POLICY_PATTERN.search(script):
            findings.error(
                "[privilege-escalation] Script references AdministratorAccess. "
                "Use scoped permissions."
            )


def _check_step_apis(step: AutomationStep, findings: Findings) -> None:
    """Check APIs declared directly in step inputs.

    Calls inside `aws:executeScript` bodies are not scanned. Passing validation
    therefore does not prove that a handler contains no destructive call.
    """
    inputs = step.get("inputs")
    api = inputs.get("Api") if isinstance(inputs, dict) else None
    if api in DANGEROUS_APIS:
        findings.advisory(
            f'[dangerous-api] Step "{_step_name(step)}" uses destructive API "{api}". '
            "Consider a less destructive alternative."
        )
    if api in DISABLE_SECURITY_APIS:
        findings.advisory(
            f'[disable-security] Step "{_step_name(step)}" uses API "{api}" which disables a '
            "security control. This is prohibited."
        )
    if api in DISCOURAGED_APIS:
        findings.hint(
            f'[discouraged-api] Step "{_step_name(step)}" uses API "{api}": '
            f"{DISCOURAGED_APIS[api]}."
        )
    # Only when no exact-match rule already spoke, so one step never
    # reports twice about the same call.
    recognised = (
        api in DANGEROUS_APIS
        or api in DISABLE_SECURITY_APIS
        or api in DISCOURAGED_APIS
        or api in LEGITIMATE_DESTRUCTIVE_APIS
    )
    if isinstance(api, str) and not recognised and DESTRUCTIVE_VERB_PATTERN.match(api):
        findings.hint(
            f'[destructive-verb] Step "{_step_name(step)}" calls "{api}", whose name '
            "suggests it removes or switches something off. If taking this away "
            "*is* the remediation, that is fine — say so in the step name or "
            "description. If it is collateral, redesign it."
        )


def _check_main_steps(doc: dict[str, Any], findings: Findings) -> None:
    main_steps = doc.get("mainSteps")
    if not isinstance(main_steps, list) or len(main_steps) == 0:
        findings.error("[main-steps] mainSteps must be a non-empty array.")
        return

    has_verify = any(
        (s.get("action") == "aws:assertAwsResourceProperty")
        or (isinstance(s.get("name"), str) and "verify" in s["name"].lower())
        for s in main_steps
        if isinstance(s, dict)
    )
    if not has_verify:
        findings.advisory(
            "[verify-step] No verification step found. Add an aws:assertAwsResourceProperty step "
            'or a step with "verify" in its name.'
        )

    for step in main_steps:
        if not isinstance(step, dict):
            continue
        _check_step_apis(step, findings)
        if step.get("action") == "aws:executeScript" and not step.get("timeoutSeconds"):
            findings.advisory(
                f'[missing-timeout] Step "{_step_name(step)}" uses aws:executeScript without '
                "timeoutSeconds. Add timeoutSeconds: 600."
            )


def _check_credential_exposure(raw: str, findings: Findings) -> None:
    lowered = raw.lower()
    for cmd in CREDENTIAL_EXPOSURE_COMMANDS:
        if cmd in lowered:
            findings.advisory(
                f'[credential-exposure] YAML contains credential-exposing command "{cmd}". '
                "Use SSM Parameter Store instead."
            )
            break


def _check_insecure_transport(raw: str, findings: Findings) -> None:
    for pat in INSECURE_PATTERNS:
        if pat.search(raw):
            findings.error(
                "[insecure-transport] YAML disables SSL verification or uses insecure flags. "
                "Always use HTTPS with certificate validation."
            )
            break


def validate(
    runbook_yaml: str, strict: bool = True, mode: RunbookMode = "custom"
) -> ValidationResult:
    """Runs every rule against one runbook. The rule order below is the report order.

    `mode` selects which rules apply, not how loudly they report: `custom` (the
    default) additionally enforces the Orchestrator's parameter contract, which a
    built-in child document is exempt from. Defaulting to `custom` keeps the
    stricter reading for a caller that does not say — a Custom Runbook is what this
    skill authors, and the exemption has to be asked for.
    """
    findings = Findings(strict)

    try:
        doc = yaml.safe_load(runbook_yaml)
    except yaml.YAMLError as err:
        return {
            "valid": False,
            "errors": [f"[yaml-parse] YAML parse error: {err}"],
            "warnings": findings.warnings,
            "schemaVersion": None,
        }
    if not isinstance(doc, dict):
        return {
            "valid": False,
            "errors": ["[yaml-parse] YAML root must be a mapping object."],
            "warnings": findings.warnings,
            "schemaVersion": None,
        }

    schema_version = _check_schema_version(doc, findings)
    _check_assume_role(doc, findings)
    _check_automation_role_param(doc, findings)
    if mode == "custom":
        _check_orchestrator_parameter_contract(doc, findings)
    # The secret, credential and transport rules read the raw text; the rest read
    # the parsed document.
    _check_hardcoded_secrets(runbook_yaml, findings)
    _check_privilege_escalation(doc, findings)
    _check_main_steps(doc, findings)
    _check_credential_exposure(runbook_yaml, findings)
    _check_insecure_transport(runbook_yaml, findings)

    return {
        "valid": len(findings.errors) == 0,
        "errors": findings.errors,
        "warnings": findings.warnings,
        "schemaVersion": schema_version,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_runbook.py",
        description="Validate an SSM Automation runbook against the ASR rules.",
    )
    parser.add_argument("runbook", help="Path to the runbook YAML to validate.")
    # `store_true` rather than scanning `argv` for the string: a scan cannot tell
    # `--lenient` from `--lennient`, so a typo would silently validate in strict
    # mode and read as though the escape hatch had been taken.
    parser.add_argument(
        "--lenient",
        action="store_true",
        help="Downgrade advisory findings to warnings. Hard rules still fail.",
    )
    parser.add_argument(
        "--mode",
        choices=("custom", "builtin"),
        default="custom",
        help=(
            "custom (default): also enforce the Orchestrator parameter contract. "
            "builtin: exempt it, for a child document invoked behind a wrapper "
            "that has already parsed the finding."
        ),
    )
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit as error:
        return error.code if isinstance(error.code, int) else 2
    try:
        with open(args.runbook, encoding="utf-8") as fh:
            content = fh.read()
    except OSError as err:
        print(f"validate_runbook: cannot read {args.runbook}: {err}", file=sys.stderr)
        return 2
    result = validate(content, strict=not args.lenient, mode=args.mode)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
