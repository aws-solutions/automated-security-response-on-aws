# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/validate_runbook.py.

Determinism is the whole point of this tool (same input -> same verdict), so the
tests assert on the specific rule code emitted, not just on validity. Each
invalid fixture is crafted to trip exactly one rule; the parametrised test binds
fixture -> expected rule code so a rule regression names the offending fixture.
"""
from __future__ import annotations

import itertools
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import validate_runbook  # noqa: E402  (path injected by conftest)

# fixture filename (under fixtures/invalid) -> rule code it must emit as an ERROR
# in strict mode. These are the machine-checkable "result validity" assertions.
INVALID_CASES = {
    "wrong_schema_version.yaml": "[schema-version]",
    "missing_assume_role.yaml": "[assume-role]",
    "missing_role_param.yaml": "[automation-role-param]",
    "missing_finding_param.yaml": "[orchestrator-parameters]",
    "required_param_without_default.yaml": "[orchestrator-parameters]",
    "hardcoded_access_key.yaml": "[hardcoded-secret]",
    "hardcoded_password_assignment.yaml": "[hardcoded-secret]",
    "hardcoded_password_unquoted.yaml": "[hardcoded-secret]",
    "wildcard_iam_script.yaml": "[privilege-escalation]",
    "wildcard_iam_script_multiline.yaml": "[privilege-escalation]",
    "wildcard_iam_script_quoted.yaml": "[privilege-escalation]",
    "wildcard_iam_script_deny_plus_allow.yaml": "[privilege-escalation]",
    "admin_policy_script.yaml": "[privilege-escalation]",
    "empty_main_steps.yaml": "[main-steps]",
    "insecure_transport.yaml": "[insecure-transport]",
    "missing_verify_step.yaml": "[verify-step]",
    "broken_yaml.yaml": "[yaml-parse]",
}

# fixture filename (under fixtures/valid) -> why it is a false-positive risk.
# Each is modelled on a real shipped ASR runbook that the rules once wrongly
# rejected, so these assert the ABSENCE of a finding.
VALID_CASES = {
    "s3_versioning.yaml": "baseline well-formed runbook",
    "principal_wildcard_bucket_policy.yaml": '"Principal": "*" is required by a TLS-only deny policy',
    "deny_wildcard_action_policy.yaml": '"Action": "*" under Deny removes privilege rather than granting it',
    "iam_password_policy.yaml": '"...Password" keys hold configuration, not credentials',
}


# `inputs.Api` value -> (rule code, where it must land) for a step calling it,
# or None for "no finding at all". The severity is half the assertion:
#   "error"   -> blocking in strict mode, the exact-match rules
#   "warning" -> a hint, a warning in BOTH modes, so it can never fail a run
#
# The split is what makes a general verb rule safe to ship. `DeleteFooBar` gets a
# hint because nobody can know whether deleting a FooBar is the fix; `DeleteBucket`
# gets an error because everybody does. The three audited APIs that a naive
# `Delete*` gate would have rejected — all shipped, all correct — are pinned below
# as silent, since they are named in LEGITIMATE_DESTRUCTIVE_APIS.
API_CASES = {
    "DeleteBucket": ("[dangerous-api]", "error"),
    "TerminateInstances": ("[dangerous-api]", "error"),
    "DeleteStack": ("[dangerous-api]", "error"),
    "StopLogging": ("[disable-security]", "error"),
    "DeleteTrail": ("[disable-security]", "error"),
    # Legitimate call, wrong tool for the job — a weaker claim, so a hint.
    "PutBucketAcl": ("[discouraged-api]", "warning"),
    # Unknown verb-matching APIs: the general rule, hinting rather than gating.
    "DeleteFooBar": ("[destructive-verb]", "warning"),
    "DisableSomeFeature": ("[destructive-verb]", "warning"),
    "DeregisterTargets": ("[destructive-verb]", "warning"),
    # Deleting the resource IS the remediation. Verified as real `inputs.Api`
    # values in EncryptRDSSnapshot.yaml and the two AutoScaling launch-config
    # runbooks, which is why a prefix gate could not have shipped bare.
    "DeleteDBSnapshot": None,
    "DeleteDBClusterSnapshot": None,
    "DeleteLaunchConfiguration": None,
    # Called from shipped `aws:executeScript` handlers rather than as `inputs.Api`,
    # and exempted so refactoring one into an executeAwsApi step stays quiet.
    "DeleteLoginProfile": None,
    "RemovePermission": None,
    "RevokeSecurityGroupIngress": None,
    # No destructive verb, so the rule must not reach it at all.
    "GetBucketVersioning": None,
    "PutBucketEncryption": None,
}


def _runbook_calling(api: str) -> str:
    """A strict-valid runbook whose one action step calls `api`.

    Built around a verify step so the only finding a case can produce is the one
    under test — otherwise every API case would also trip `verify-step`.
    """
    return "\n".join(
        [
            'schemaVersion: "0.3"',
            f"description: Runbook exercising {api}.",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "parameters:",
            "  AutomationAssumeRole:",
            "    type: String",
            "    description: IAM role for automation execution",
            "  Finding:",
            "    type: StringMap",
            "    description: (Required) The ASFF finding, from the Orchestrator.",
            "mainSteps:",
            "  - name: Remediate",
            "    action: aws:executeAwsApi",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Service: example",
            f"      Api: {api}",
            "  - name: VerifyResource",
            "    action: aws:assertAwsResourceProperty",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Service: s3",
            "      Api: GetBucketVersioning",
            '      PropertySelector: "$.Status"',
            "      DesiredValues:",
            "        - Enabled",
            "",
        ]
    )


# The partitions ASR is supported in. `references/validation-rules.md` names all
# three under privilege-escalation, so all three are asserted rather than assumed.
ASR_PARTITIONS = ["aws", "aws-us-gov", "aws-cn"]


def _admin_policy_runbook(partition: str) -> str:
    """A strict-valid runbook that attaches AdministratorAccess in `partition`.

    Carries a verify step for the same reason `_runbook_calling` does: the only
    finding it can produce is the one under test.
    """
    return "\n".join(
        [
            'schemaVersion: "0.3"',
            f"description: Runbook attaching AdministratorAccess in {partition}.",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "parameters:",
            "  AutomationAssumeRole:",
            "    type: String",
            "    description: IAM role for automation execution",
            "  Finding:",
            "    type: StringMap",
            "    description: (Required) The ASFF finding, from the Orchestrator.",
            "mainSteps:",
            "  - name: AttachPolicy",
            "    action: aws:executeScript",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Runtime: python3.11",
            "      Handler: handler",
            "      Script: |",
            "        import boto3",
            "        def handler(event, context):",
            "            boto3.client('iam').attach_role_policy(",
            "                RoleName=event['RoleName'],",
            f'                PolicyArn="arn:{partition}:iam::aws:policy/AdministratorAccess",',
            "            )",
            "  - name: VerifyResource",
            "    action: aws:assertAwsResourceProperty",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Service: s3",
            "      Api: GetBucketVersioning",
            '      PropertySelector: "$.Status"',
            "      DesiredValues:",
            "        - Enabled",
            "",
        ]
    )


def _run_cli(scripts_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(scripts_dir / "validate_runbook.py"), *args],
        capture_output=True,
        text=True,
    )


# --- pure-function verdicts --------------------------------------------------


def test_valid_runbook_passes_strict(valid_runbook_yaml: str) -> None:
    # GIVEN a well-formed runbook / WHEN validated strictly / THEN it is valid.
    result = validate_runbook.validate(valid_runbook_yaml, strict=True)
    assert result["valid"] is True
    assert result["errors"] == []
    assert result["schemaVersion"] == "0.3"


@pytest.mark.parametrize("filename,expected_code", sorted(INVALID_CASES.items()))
def test_invalid_fixture_emits_expected_rule(
    fixtures_dir: Path, filename: str, expected_code: str
) -> None:
    # GIVEN a fixture crafted to break one rule / WHEN validated strictly /
    # THEN it is invalid AND the specific rule code is present.
    content = (fixtures_dir / "invalid" / filename).read_text(encoding="utf-8")
    result = validate_runbook.validate(content, strict=True)
    assert result["valid"] is False
    assert any(
        err.startswith(expected_code) for err in result["errors"]
    ), f"{filename}: expected {expected_code} in errors, got {result['errors']}"


@pytest.mark.parametrize("partition", ASR_PARTITIONS)
def test_admin_policy_is_caught_in_every_supported_partition(partition: str) -> None:
    """One assertion per partition ASR runs in, not one fixture per partition.

    `ADMIN_POLICY_PATTERN` reads the partition generically (`arn:aws[\\w-]*:`), so
    every partition trips the same branch and a near-identical YAML fixture beside
    `admin_policy_script.yaml` would only re-exercise it — which is why there is no
    `_govcloud` or `_china` fixture. What is worth pinning is the documented
    promise: `validation-rules.md` names all three partitions, and rewriting the
    pattern as an alternation — the obvious "clearer" refactor — would silently drop
    whichever one the author forgot. Parametrising here fails that rewrite for every
    partition it omits.
    """
    result = validate_runbook.validate(_admin_policy_runbook(partition), strict=True)
    assert result["valid"] is False, f"{partition}: escalation not caught"
    assert [e.split("]")[0] + "]" for e in result["errors"]] == [
        "[privilege-escalation]"
    ], f"{partition}: want only privilege-escalation, got {result['errors']}"


@pytest.mark.parametrize("filename,rationale", sorted(VALID_CASES.items()))
def test_valid_fixture_has_no_findings(
    fixtures_dir: Path, filename: str, rationale: str
) -> None:
    # GIVEN a runbook shape that is legitimate but trips a naive pattern /
    # WHEN validated strictly / THEN there are no findings at all.
    content = (fixtures_dir / "valid" / filename).read_text(encoding="utf-8")
    result = validate_runbook.validate(content, strict=True)
    assert (
        result["valid"] is True
    ), f"{filename} ({rationale}) must be strict-valid, got {result['errors']}"


@pytest.mark.parametrize("api,expected", sorted(API_CASES.items()))
def test_api_rules_report_at_the_right_severity(
    api: str, expected: tuple[str, str] | None
) -> None:
    # GIVEN a step calling one AWS API / WHEN validated strictly / THEN the rule
    # that fires, and whether it blocks, are both as specified.
    result = validate_runbook.validate(_runbook_calling(api), strict=True)
    if expected is None:
        assert result["valid"] is True, f"{api} must not be flagged: {result['errors']}"
        assert result["warnings"] == [], f"{api} must be silent: {result['warnings']}"
        return
    code, tier = expected
    bucket = result["errors"] if tier == "error" else result["warnings"]
    other = result["warnings"] if tier == "error" else result["errors"]
    assert any(
        f.startswith(code) for f in bucket
    ), f"{api}: want {code} in {tier}s, got {result}"
    assert not any(f.startswith(code) for f in other), f"{api}: {code} in both buckets"


@pytest.mark.parametrize(
    "api", [a for a, e in API_CASES.items() if e and e[1] == "warning"]
)
def test_hints_never_block_in_either_mode(api: str) -> None:
    """The property the whole tier exists for: a hint cannot fail a run.

    An advisory is an error until `--lenient`. A hint is a warning in both modes,
    because `[destructive-verb]` and `[discouraged-api]` infer a problem from a
    name — and if inference could gate, an author holding a legitimate
    `DeleteSomething` would reach for `--lenient`, silencing the rules that are
    certain along with the one that guessed.
    """
    for strict in (True, False):
        result = validate_runbook.validate(_runbook_calling(api), strict=strict)
        assert result["valid"] is True, f"{api} blocked with strict={strict}"
        assert result["errors"] == []
        assert result["warnings"], f"{api} produced no hint at all"


def test_api_rule_categories_do_not_overlap() -> None:
    # One API in two categories would report twice for one step, with two
    # different severities implied by two different messages.
    categories = {
        "dangerous": set(validate_runbook.DANGEROUS_APIS),
        "disable-security": set(validate_runbook.DISABLE_SECURITY_APIS),
        "discouraged": set(validate_runbook.DISCOURAGED_APIS),
        "legitimate": set(validate_runbook.LEGITIMATE_DESTRUCTIVE_APIS),
    }
    for left, right in itertools.combinations(sorted(categories), 2):
        overlap = categories[left] & categories[right]
        assert not overlap, f"{left} and {right} both claim {sorted(overlap)}"


def test_every_exemption_would_otherwise_be_hinted() -> None:
    """No dead weight in the exemption list, and no false sense of coverage.

    An entry that does not match `DESTRUCTIVE_VERB_PATTERN` suppresses nothing, so
    it is either a typo or a misunderstanding of what the list does — the danger
    being someone adding `PutBucketAcl` here expecting it to silence
    `[discouraged-api]`, which exemption does not touch.
    """
    unreachable = [
        api
        for api in validate_runbook.LEGITIMATE_DESTRUCTIVE_APIS
        if not validate_runbook.DESTRUCTIVE_VERB_PATTERN.match(api)
    ]
    assert not unreachable, f"exempted but never hinted anyway: {unreachable}"


def test_exemption_cannot_suppress_a_blocking_rule() -> None:
    """Exemption silences the hint only — it is not a bypass for `dangerous-api`.

    Pinned because the two mechanisms look interchangeable from the call site. If
    exemption ever short-circuited the exact-match rules, adding an entry here
    would quietly disarm the gate instead of quieting a guess.
    """
    patched = dict(validate_runbook.LEGITIMATE_DESTRUCTIVE_APIS)
    patched["DeleteBucket"] = "pretend someone exempted it"
    original = validate_runbook.LEGITIMATE_DESTRUCTIVE_APIS
    validate_runbook.LEGITIMATE_DESTRUCTIVE_APIS = patched
    try:
        result = validate_runbook.validate(
            _runbook_calling("DeleteBucket"), strict=True
        )
    finally:
        validate_runbook.LEGITIMATE_DESTRUCTIVE_APIS = original
    assert result["valid"] is False
    assert any(e.startswith("[dangerous-api]") for e in result["errors"])


def test_api_rules_do_not_read_script_bodies() -> None:
    """A documented limitation, pinned so it cannot become a silent surprise.

    The API rules read `inputs.Api`; a `boto3` call inside an `aws:executeScript`
    body is not matched against them, and most ASR remediation logic lives there.
    `references/validation-rules.md` says so under "What each rule reads". If this
    test starts failing because body scanning was added, update that section — the
    danger is an author trusting a clean report as proof the handler is safe.
    """
    runbook = "\n".join(
        [
            'schemaVersion: "0.3"',
            "description: Handler that deletes a bucket from a script body.",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "parameters:",
            "  AutomationAssumeRole:",
            "    type: String",
            "    description: IAM role for automation execution",
            "  Finding:",
            "    type: StringMap",
            "    description: (Required) The ASFF finding, from the Orchestrator.",
            "mainSteps:",
            "  - name: VerifyAndRemediate",
            "    action: aws:executeScript",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Runtime: python3.11",
            "      Handler: handler",
            "      Script: |",
            "        import boto3",
            "        def handler(event, context):",
            "            boto3.client('s3').delete_bucket(Bucket=event['Bucket'])",
            "",
        ]
    )
    result = validate_runbook.validate(runbook, strict=True)
    assert result["valid"] is True, result["errors"]


def test_script_bodies_reads_both_yaml_serializations(fixtures_dir: Path) -> None:
    # A block scalar and the quoted form ssm:GetDocument returns must yield the
    # same script body, so no rule can be blind to one of them.
    import yaml  # type: ignore[import-untyped]

    block = yaml.safe_load(
        (fixtures_dir / "invalid" / "wildcard_iam_script_multiline.yaml").read_text(
            encoding="utf-8"
        )
    )
    quoted = yaml.safe_load(
        (fixtures_dir / "invalid" / "wildcard_iam_script_quoted.yaml").read_text(
            encoding="utf-8"
        )
    )
    for doc in (block, quoted):
        bodies = validate_runbook.script_bodies(doc)
        assert len(bodies) == 1
        assert '"Action": "*"' in bodies[0]


@pytest.mark.parametrize(
    "doc,why",
    [
        ({}, "no mainSteps at all"),
        ({"mainSteps": None}, "mainSteps present but null"),
        ({"mainSteps": ["not-a-mapping"]}, "step is a string, not a mapping"),
        ({"mainSteps": [{"name": "NoInputs"}]}, "step has no inputs"),
        ({"mainSteps": [{"inputs": "not-a-mapping"}]}, "inputs is not a mapping"),
        ({"mainSteps": [{"inputs": {"Script": 42}}]}, "Script is not a string"),
    ],
)
def test_script_bodies_tolerates_malformed_steps(doc: dict[str, Any], why: str) -> None:
    # script_bodies runs before the shape rules have rejected anything, so it
    # must never raise on a malformed document — it just finds no bodies.
    assert validate_runbook.script_bodies(doc) == [], why


def test_a_step_name_that_is_not_a_string_still_reports_as_unnamed() -> None:
    # YAML reads `name: 42` as an int, and the API rules quote the step name in
    # every message they emit. The name is the one field no rule validates, so the
    # rules have to render whatever is there rather than assume a string.
    numeric_name = _runbook_calling("DeleteBucket").replace(
        "  - name: Remediate", "  - name: 42"
    )

    result = validate_runbook.validate(numeric_name, strict=True)

    assert any('"(unnamed)"' in e for e in result["errors"]), result["errors"]


def _runbook_whose_handler_does(*body_lines: str) -> str:
    """A strict-valid runbook whose `aws:executeScript` body is `body_lines`.

    The raw-text rules read script bodies, so this is the seam for asserting on
    what a handler's own code looks like rather than on document keys.
    """
    return "\n".join(
        [
            'schemaVersion: "0.3"',
            "description: Handler under test.",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "parameters:",
            "  AutomationAssumeRole:",
            "    type: String",
            "    description: IAM role for automation execution",
            "  Finding:",
            "    type: StringMap",
            "    description: (Required) The ASFF finding, from the Orchestrator.",
            "mainSteps:",
            "  - name: VerifyAndRemediate",
            "    action: aws:executeScript",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Runtime: python3.11",
            "      Handler: handler",
            "      Script: |",
            "        import boto3",
            "        def handler(event, context):",
            *(f"            {line}" for line in body_lines),
            "",
        ]
    )


@pytest.mark.parametrize(
    "assignment",
    [
        'password = os.environ["DB_PASSWORD"]',
        "password=$DB_PASSWORD",
        'master_user_password = event["Password"]',
        "password = secrets.token_urlsafe(32)",
    ],
)
def test_an_unquoted_secret_read_from_elsewhere_is_not_a_hardcoded_one(
    assignment: str,
) -> None:
    # The unquoted half of the rule has to tell `MasterUserPassword: hunter2` from
    # a handler that reads a password instead of spelling one out. These four are
    # how a correct remediation gets a credential, and flagging them would put a
    # hard error — one with no `--lenient` escape — on the right answer.
    runbook = _runbook_whose_handler_does(assignment, "return {'ok': True}")

    result = validate_runbook.validate(runbook, strict=True)

    assert not [e for e in result["errors"] if "[hardcoded-secret]" in e], result[
        "errors"
    ]


def test_quotes_around_the_same_value_still_report_it() -> None:
    # The exemption above is for unquoted values only: inside quotes `$DB_PASSWORD`
    # is a literal string, and a handler assigning one is assigning a secret.
    runbook = _runbook_whose_handler_does('password = "$DB_PASSWORD"')

    result = validate_runbook.validate(runbook, strict=True)

    assert any("[hardcoded-secret]" in e for e in result["errors"]), result["errors"]


def test_determinism_same_input_same_verdict(fixtures_dir: Path) -> None:
    # The determinism guarantee: repeated validation yields byte-identical reports.
    content = (fixtures_dir / "invalid" / "wildcard_iam_script.yaml").read_text(
        encoding="utf-8"
    )
    first = validate_runbook.validate(content, strict=True)
    for _ in range(4):
        assert validate_runbook.validate(content, strict=True) == first


def test_lenient_downgrades_advisory_to_warning(fixtures_dir: Path) -> None:
    # The missing-verify rule is advisory: an error in strict, a warning in lenient.
    content = (fixtures_dir / "invalid" / "missing_verify_step.yaml").read_text(
        encoding="utf-8"
    )
    strict = validate_runbook.validate(content, strict=True)
    lenient = validate_runbook.validate(content, strict=False)
    assert strict["valid"] is False
    assert lenient["valid"] is True
    assert any("[verify-step]" in w for w in lenient["warnings"])


# --- CLI contract (exit codes) -----------------------------------------------


def test_cli_exit_zero_on_valid(
    scripts_dir: Path, tmp_path: Path, valid_runbook_yaml: str
) -> None:
    f = tmp_path / "ok.yaml"
    f.write_text(valid_runbook_yaml, encoding="utf-8")
    proc = _run_cli(scripts_dir, str(f))
    assert proc.returncode == 0


def test_cli_exit_one_on_invalid(scripts_dir: Path, fixtures_dir: Path) -> None:
    proc = _run_cli(
        scripts_dir, str(fixtures_dir / "invalid" / "hardcoded_access_key.yaml")
    )
    assert proc.returncode == 1


def test_cli_exit_two_on_usage_errors(scripts_dir: Path, tmp_path: Path) -> None:
    # No file argument and a path that does not exist are both usage errors, kept
    # distinct from exit 1 (the file was read and is invalid) so that a mistyped
    # path can never be mistaken for a validation failure.
    assert _run_cli(scripts_dir).returncode == 2
    assert _run_cli(scripts_dir, str(tmp_path / "nope.yaml")).returncode == 2


def test_cli_rejects_misspelled_flag_instead_of_running_strict(
    scripts_dir: Path, fixtures_dir: Path
) -> None:
    """A typo'd `--lenient` must fail, not silently validate in strict mode.

    The failure this guards is quiet: the author asks for lenient, gets strict,
    and reads the resulting advisory error as a real defect in their runbook.
    Pairing the two cases is the point — the typo has to be rejected *and* the
    correct spelling has to still take effect.
    """
    advisory = str(fixtures_dir / "invalid" / "missing_verify_step.yaml")
    assert _run_cli(scripts_dir, advisory, "--lennient").returncode == 2
    assert _run_cli(scripts_dir, advisory).returncode == 1
    assert _run_cli(scripts_dir, advisory, "--lenient").returncode == 0


def _errors(fixtures_dir: Path, name: str, **kwargs: Any) -> list[str]:
    content = (fixtures_dir / "invalid" / name).read_text(encoding="utf-8")
    return validate_runbook.validate(content, **kwargs)["errors"]


def test_orchestrator_contract_is_exempt_in_builtin_mode(fixtures_dir: Path) -> None:
    """A built-in child document may take resource parameters; a Custom Runbook may not.

    The distinction is applicability, not confidence, which is why it is a mode and
    not an advisory severity: `--lenient` would also silence unrelated rules, and a
    built-in author would be reading a warning about a contract that does not apply
    to them. Both directions are asserted, because a mode that exempts everything
    would pass the first half alone.
    """
    for fixture in (
        "missing_finding_param.yaml",
        "required_param_without_default.yaml",
    ):
        assert any(
            "[orchestrator-parameters]" in e for e in _errors(fixtures_dir, fixture)
        ), f"{fixture} must trip the rule in the default (custom) mode"
        assert not any(
            "[orchestrator-parameters]" in e
            for e in _errors(fixtures_dir, fixture, mode="builtin")
        ), f"{fixture} must be exempt in builtin mode"


def test_orchestrator_contract_names_every_offending_parameter(
    fixtures_dir: Path,
) -> None:
    """The message has to name the parameter, since the fix differs per parameter.

    `BucketName` should be derived from the finding; a `KmsKeyId` should get a
    default. A rule that only said "a required parameter" would leave the author
    guessing which, in a document that may declare several.
    """
    missing_finding = _errors(fixtures_dir, "missing_finding_param.yaml")
    assert any("parameters.Finding is required" in e for e in missing_finding)
    assert any("parameters.BucketName is required" in e for e in missing_finding)

    # Declaring Finding satisfies only the first half of the contract.
    defaulted = _errors(fixtures_dir, "required_param_without_default.yaml")
    assert not any("parameters.Finding is required" in e for e in defaulted)
    assert any("parameters.KmsKeyId is required" in e for e in defaulted)


def test_orchestrator_contract_stays_silent_when_parameters_are_absent() -> None:
    """No `parameters` section at all is [automation-role-param]'s finding, reported once.

    Two rules describing one absence reads as two defects, and the author fixes the
    section once. This is why the rule returns early rather than treating a missing
    section as a missing `Finding`.

    Note the contrast with `missing_role_param.yaml`, which *does* have a
    `parameters` section (holding only `BucketName`): there both rules correctly
    fire, because there are genuinely two separate defects to fix.
    """
    no_params = "\n".join(
        [
            'schemaVersion: "0.3"',
            "description: Runbook with no parameters section at all.",
            'assumeRole: "{{ AutomationAssumeRole }}"',
            "mainSteps:",
            "  - name: VerifyResource",
            "    action: aws:assertAwsResourceProperty",
            "    timeoutSeconds: 600",
            "    inputs:",
            "      Service: s3",
            "      Api: GetBucketVersioning",
            '      PropertySelector: "$.Status"',
            "      DesiredValues:",
            "        - Enabled",
            "",
        ]
    )
    errors = validate_runbook.validate(no_params)["errors"]
    assert any("[automation-role-param]" in e for e in errors)
    assert not any("[orchestrator-parameters]" in e for e in errors)
