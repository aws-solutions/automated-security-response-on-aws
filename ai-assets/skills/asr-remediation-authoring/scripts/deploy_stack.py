#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Manage ASR stacks in a confirmed non-production AWS account.

This non-interactive wrapper uses the repository's deployment scripts and adds
account verification before resource changes.

Actions:
  status        — Check if stacks exist and report their state
  init          — Create local-config.json + S3 buckets (first-time setup)
  deploy        — Build and deploy all stacks (create or update)
  delete        — Delete all stacks
  deploy-member — Create or update only the member stack, in one other Region

Usage:
    python3 scripts/deploy_stack.py status
    python3 scripts/deploy_stack.py status --region us-west-2
    python3 scripts/deploy_stack.py init --account-id 123456789012 --region us-east-1 --email admin@example.com
    python3 scripts/deploy_stack.py deploy
    python3 scripts/deploy_stack.py deploy-member --region us-west-2
    python3 scripts/deploy_stack.py delete

Use `deploy-member` for each additional account and Region where findings should
be remediated. See `references/deployment-topology.md` for stack placement.

Requires:
  - AWS credentials for a non-production account, and for the same account
    named by --account-id / local-config.json — a mismatch is refused
  - Node.js and npm available (for the build)
  - `npm install` already run in source/
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import TypedDict, cast

from account_guard import ACCOUNT_ID_PATTERN, check_identity
from solution_checkout import CheckoutNotFoundError, resolve_checkout_root


class LocalConfig(TypedDict, total=False):
    """The `deployment/dev/local-config.json` keys this script writes and reads.

    `total=False` because the file is hand-editable and is read back on later
    runs, so any key can be absent — every reader goes through `.get()` with a
    default for exactly that reason. The value of naming the keys is that
    `config.get("acount_id")` becomes a `mypy` error instead of a silent `None`
    that surfaces as a stack deployed into the wrong account.
    """

    accountId: str
    region: str
    namespace: str
    baseBucketName: str
    templateBucketName: str
    assetBucketName: str
    solutionName: str
    solutionVersion: str
    secHubAdminAccount: str
    adminUserEmail: str


def resolve_repo_root() -> Path:
    """Locate the ASR solution checkout the stacks are deployed from.

    `ASR_WORKSPACE_ROOT` wins when set and must itself be a checkout. Otherwise
    searches above the current directory, then above this script — the latter covers
    the skill installed inside the checkout (`ai-assets/…`, `.kiro/skills/…`,
    `.claude/skills/…`, `.agents/skills/…`). Fixing a directory depth instead broke
    as soon as the skill lived anywhere else, such as a user-level `~/.kiro/skills`.
    """
    try:
        return resolve_checkout_root([Path.cwd(), Path(__file__).resolve().parent])
    except CheckoutNotFoundError as error:
        raise SystemExit(str(error)) from error


REPO_ROOT = resolve_repo_root()
DEPLOYMENT_DIR = REPO_ROOT / "deployment"
DEV_DIR = DEPLOYMENT_DIR / "dev"
CONFIG_FILE = DEV_DIR / "local-config.json"
INIT_SCRIPT = DEV_DIR / "init.sh"
DEPLOY_SCRIPT = DEV_DIR / "deploy-dev.sh"
UPLOAD_SCRIPT = DEPLOYMENT_DIR / "upload-s3-dist.sh"
REGIONAL_ASSETS_DIR = DEPLOYMENT_DIR / "regional-s3-assets"
GLOBAL_ASSETS_DIR = DEPLOYMENT_DIR / "global-s3-assets"
# A stack in one of these states exists but cannot be updated; CloudFormation
# rejects update-stack and the only way forward is to delete it.
# AWS Region codes: `us-east-1`, `eu-central-1`, `us-gov-west-1`, `ap-southeast-3`.
# --region goes straight into S3 bucket names, the template URL, and CLI arguments,
# so a malformed value would otherwise surface as a confusing bucket-naming or
# endpoint error several steps later — the same reason `init` guards --account-id.
REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d$")


def _region_arg(value: str) -> str:
    """argparse type for --region: rejects anything that is not a Region code."""
    if not REGION_PATTERN.match(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not an AWS Region code (expected e.g. us-west-2)"
        )
    return value


NON_UPDATABLE_STACK_STATUSES = frozenset(
    {"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "DELETE_FAILED"}
)

MEMBER_TEMPLATE_FILE = "automated-security-response-member.template"

# Mirrors `MEMBER_PARAMS` in deployment/dev/deploy-dev.sh. A second-Region member
# stack must carry the same playbook selection as the first, or the two Regions
# remediate different control sets from one admin stack.
#
# `EnableCloudTrailForASRActionLog` stays `no` for a reason beyond taste: its bucket
# is named `so0111-asr-<namespace>-management-events-<account>` with no Region
# segment (source/lib/member/cloud-trail.ts), so turning it on in a second Region
# collides with the first Region's bucket in S3's global namespace.
MEMBER_PLAYBOOK_PARAMETERS: tuple[tuple[str, str], ...] = (
    ("LoadSCMemberStack", "yes"),
    ("LoadAFSBPMemberStack", "no"),
    ("LoadCIS120MemberStack", "no"),
    ("LoadCIS140MemberStack", "no"),
    ("LoadCIS300MemberStack", "no"),
    ("LoadNIST80053MemberStack", "no"),
    ("LoadPCI321MemberStack", "no"),
    ("CreateS3BucketForRedshiftAuditLogging", "no"),
    ("EnableCloudTrailForASRActionLog", "no"),
)


def _read_config() -> LocalConfig | None:
    """Read local-config.json if it exists.

    Every caller indexes the result by key, so a file that parsed to a list or a
    bare string would fail later with an unrelated `TypeError`. Validating the
    shape here names the actual problem — and is what lets the return type be a
    mapping rather than `json.loads`'s `Any`.

    The `LocalConfig` cast is a claim about the keys, not a check of them: JSON
    gives no per-key guarantee and validating ten optional keys here would buy
    nothing, since every reader already supplies a default. What it does buy is a
    misspelled key failing at the call site.
    """
    if not CONFIG_FILE.exists():
        return None
    parsed = json.loads(CONFIG_FILE.read_text())
    if not isinstance(parsed, dict):
        raise ValueError(
            f"{CONFIG_FILE} must contain a JSON object, got {type(parsed).__name__}"
        )
    return cast(LocalConfig, parsed)


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a shell command and return the result."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _verify_non_production(expected_account_id: str) -> tuple[bool, str]:
    """Verify the credentials point at the non-production account the caller named.

    Calls `sts get-caller-identity` through the `aws` CLI and hands the result to
    `account_guard.check_identity`, which is shared with `e2e_authoring_flow.py`
    and documents why the check is an equality test rather than a marker scan. The
    caller names the account with `--account-id` for `init`, or `accountId` in
    `local-config.json` for `deploy`/`delete`.
    """
    # `check_identity` re-checks this, but doing it here too keeps a malformed
    # config from spending an AWS call to reach a verdict already known.
    if not ACCOUNT_ID_PATTERN.match(expected_account_id):
        return check_identity(None, expected_account_id)

    result = _run(["aws", "sts", "get-caller-identity"], check=False)
    if result.returncode != 0:
        return False, f"AWS credentials invalid: {result.stderr.strip()}"
    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return False, f"could not parse sts get-caller-identity output: {error}"

    return check_identity(identity, expected_account_id)


def _ensure_private_bucket(bucket: str, *, region: str) -> str | None:
    """Create `bucket` in `region` if absent and block public access on it.

    Returns an error message, or `None` when the bucket exists and is private.
    Shared by `init` and `deploy-member` because both need a staging bucket in a
    Region: Lambda requires its code bucket to be in the same Region as the
    function, so each Region ASR is deployed into needs its own asset bucket.
    """
    create_cmd = [
        "aws",
        "s3api",
        "create-bucket",
        "--bucket",
        bucket,
        "--region",
        region,
    ]
    if region != "us-east-1":
        create_cmd += ["--create-bucket-configuration", f"LocationConstraint={region}"]
    result = _run(create_cmd, check=False)
    if result.returncode != 0 and "BucketAlreadyOwnedByYou" not in result.stderr:
        return f"creating {bucket}: {result.stderr.strip()}"

    # A failure here is fatal: the bucket now exists and is about to hold
    # CloudFormation templates and Lambda assets, so silently continuing would
    # leave it reachable with public ACLs still allowed.
    result = _run(
        [
            "aws",
            "s3api",
            "put-public-access-block",
            "--bucket",
            bucket,
            "--region",
            region,
            "--public-access-block-configuration",
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ],
        check=False,
    )
    if result.returncode != 0:
        return (
            f"{bucket} exists but public access is NOT blocked: "
            f"{result.stderr.strip()}\n"
            f"  Block it or delete the bucket before deploying."
        )
    return None


class StackStatusUnavailable(Exception):
    """describe-stacks failed for a reason other than the stack not existing.

    Throttling, expired credentials, a denied call, or output that cannot be parsed.
    None of these say whether the stack exists, so a caller deciding between create
    and update must stop rather than guess.
    """


def _describe_stack_status(stack_name: str, *, region: str) -> str | None:
    """Return `stack_name`'s status in `region`, or `None` when it does not exist.

    Raises `StackStatusUnavailable` when the answer is unknown. Only the CLI's
    "does not exist" error means not-found; every other failure used to collapse to
    `None`, which read as "no stack" and routed a transient error to `create-stack`.
    """
    result = _run(
        [
            "aws",
            "cloudformation",
            "describe-stacks",
            "--stack-name",
            stack_name,
            "--region",
            region,
        ],
        check=False,
    )
    if result.returncode != 0:
        if "does not exist" in result.stderr:
            return None
        raise StackStatusUnavailable(
            f"describe-stacks {stack_name} in {region} failed: "
            f"{result.stderr.strip() or f'exit {result.returncode}'}"
        )
    try:
        return str(json.loads(result.stdout)["Stacks"][0]["StackStatus"])
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        raise StackStatusUnavailable(
            f"describe-stacks {stack_name} in {region} returned unreadable output"
        ) from exc


def cmd_status(args: argparse.Namespace) -> int:
    """Check stack status."""
    config = _read_config()
    if config is None:
        print("No local-config.json found. Run 'init' first.")
        print(
            f"  python3 {__file__} init --account-id <ID> --region <REGION> --email <EMAIL>"
        )
        return 1

    config_region = config.get("region", "us-east-1")
    # Without the override this reports only the config Region, so a member stack
    # deployed by `deploy-member` into another Region reads as absent — which looks
    # exactly like a deployment that was never done.
    region = args.region or config_region

    print(f"Config: {CONFIG_FILE}")
    print(f"  Account:   {config.get('accountId')}")
    print(f"  Region:    {region}{'' if region == config_region else ' (override)'}")
    print(f"  Namespace: {config.get('namespace')}")
    print(f"  Version:   {config.get('solutionVersion')}")
    print()

    namespace = config.get("namespace", "")
    stacks = [
        f"ASR-Admin-{namespace}",
        f"ASR-Member-Roles-{namespace}",
        f"ASR-Member-{namespace}",
    ]

    for stack_name in stacks:
        # A traceback here would abandon the stacks not yet reported — and for a
        # status command, "could not read" is itself the status.
        try:
            status = _describe_stack_status(stack_name, region=region)
        except StackStatusUnavailable as exc:
            print(f"  ? {stack_name}: {exc}")
            continue
        if status is None:
            print(f"  ✗ {stack_name}: NOT FOUND")
        else:
            print(f"  ✓ {stack_name}: {status}")

    if region != config_region:
        print(
            "\nOnly the member stack is expected in a non-aggregation Region: "
            "the admin stack is deployed once in the Security Hub aggregation "
            "Region, and the member roles stack once per account."
        )

    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Non-interactive init: create config + S3 buckets."""
    account_id = args.account_id
    if not ACCOUNT_ID_PATTERN.match(account_id):
        # The value goes straight into S3 bucket names and the CloudFormation
        # config, where a malformed one surfaces as a confusing bucket-naming
        # error several steps later — or creates a bucket nobody expected. It is
        # also what the credentials are checked against, so it is validated
        # before the account check rather than after.
        print(
            f"REFUSED: --account-id must be 12 digits, got {account_id!r}",
            file=sys.stderr,
        )
        return 2

    is_safe, msg = _verify_non_production(account_id)
    if not is_safe:
        print(f"REFUSED: {msg}", file=sys.stderr)
        return 1
    print(f"Account verified: {msg}")

    region = args.region
    email = args.email
    sechub_admin = args.sechub_admin or account_id
    version = args.version

    namespace = str(int(time.time()))[-8:]
    base_bucket = f"asr-staging-{namespace}-{account_id}"
    template_bucket = f"{base_bucket}-reference"
    asset_bucket = f"{base_bucket}-{region}"

    # Create S3 buckets
    print("\nCreating buckets...")
    for bucket in [template_bucket, asset_bucket]:
        error = _ensure_private_bucket(bucket, region=region)
        if error is not None:
            print(f"  ERROR {error}", file=sys.stderr)
            return 1
        print(f"  ✓ {bucket}")

    # Write config. Annotated so the writer is checked against the same keys the
    # readers use — the drift this catches is a key added here and never read.
    config: LocalConfig = {
        "accountId": account_id,
        "region": region,
        "namespace": namespace,
        "baseBucketName": base_bucket,
        "templateBucketName": template_bucket,
        "assetBucketName": asset_bucket,
        "solutionName": "automated-security-response-on-aws",
        "solutionVersion": version,
        "secHubAdminAccount": sechub_admin,
        "adminUserEmail": email,
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    print(f"\n✓ Config written to {CONFIG_FILE}")
    print(f"  Namespace: {namespace}")
    print(f"\nNext: python3 {__file__} deploy")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    """Build and deploy (create or update) all stacks."""
    config = _read_config()
    if config is None:
        print("No local-config.json found. Run 'init' first.")
        return 1

    is_safe, msg = _verify_non_production(str(config.get("accountId", "")))
    if not is_safe:
        print(f"REFUSED: {msg}", file=sys.stderr)
        return 1

    # The `deploy` subparser declares `action` with `default=""`, so the attribute
    # is always present — only its emptiness needs checking.
    cmd = [str(DEPLOY_SCRIPT)]
    if args.action:
        cmd.append(args.action)

    print(f"Running: {' '.join(cmd)}")
    print(f"Account: {config.get('accountId')}, Region: {config.get('region')}")
    print("This will take 10-20 minutes...\n")

    result = subprocess.run(cmd, cwd=str(DEV_DIR), text=True)
    return result.returncode


def cmd_deploy_member(args: argparse.Namespace) -> int:
    """Create or update only the member stack, in a Region other than the config one.

    The member stack is the per-Region half of the solution: it holds the remediation
    SSM Automation documents, which must exist in the Region the finding came from.
    The admin and member roles stacks are deliberately not touched — the first is
    deployed once in the aggregation Region, and the second creates global IAM roles
    whose fixed names would collide with the copy that already exists in the account.
    """
    config = _read_config()
    if config is None:
        print("No local-config.json found. Run 'init' first.")
        return 1

    is_safe, msg = _verify_non_production(str(config.get("accountId", "")))
    if not is_safe:
        print(f"REFUSED: {msg}", file=sys.stderr)
        return 1

    region = args.region
    config_region = config.get("region", "us-east-1")
    if region == config_region:
        # Two code paths writing one stack would differ in the parameters they send,
        # so the config Region stays `deploy`'s alone.
        print(
            f"REFUSED: {region} is the Region in local-config.json. "
            f"Use 'deploy' for that Region; 'deploy-member' is for additional ones.",
            file=sys.stderr,
        )
        return 2

    namespace = config.get("namespace", "")
    try:
        return _deploy_member(args, config, namespace=namespace, region=region)
    except StackStatusUnavailable as exc:
        # Unknown is not "absent": guessing here would send create-stack at a stack
        # that may exist, or update-stack at one that may not.
        print(f"REFUSED: {exc}. Retry once describe-stacks succeeds.", file=sys.stderr)
        return 1


def _deploy_member(
    args: argparse.Namespace, config: LocalConfig, *, namespace: str, region: str
) -> int:
    """`deploy-member` after its account and Region gates; may raise StackStatusUnavailable."""
    config_region = config.get("region", "us-east-1")
    member_roles_stack = f"ASR-Member-Roles-{namespace}"
    if _describe_stack_status(member_roles_stack, region=config_region) is None:
        print(
            f"REFUSED: {member_roles_stack} not found in {config_region}. "
            f"The member stack's runbooks assume the remediation IAM roles exist; "
            f"deploy the base stacks with 'deploy' first.",
            file=sys.stderr,
        )
        return 1

    if not REGIONAL_ASSETS_DIR.is_dir():
        print(
            f"REFUSED: no build output at {REGIONAL_ASSETS_DIR}. "
            f"Run 'deploy' once to build the solution, then retry.",
            file=sys.stderr,
        )
        return 1

    # Refuse before staging anything: a create that CloudFormation will reject over
    # pre-existing member resources should not first pay for the asset upload or
    # leave a freshly created staging bucket behind. An update owns those resources
    # already, so only a create is checked.
    stack_name = f"ASR-Member-{namespace}"
    status = _describe_stack_status(stack_name, region=region)
    if status in NON_UPDATABLE_STACK_STATUSES:
        print(
            _stuck_stack_refusal(stack_name, region=region, status=status),
            file=sys.stderr,
        )
        return 1
    if status is None:
        collisions = check_member_stack_collisions(
            str(config.get("accountId", "")), region=region
        )
        if collisions:
            print(
                _collision_refusal(stack_name, region=region, collisions=collisions),
                file=sys.stderr,
            )
            return 1

    base_bucket = config.get("baseBucketName", "")
    asset_bucket = f"{base_bucket}-{region}"
    print(f"Staging assets for {region}...")
    error = _ensure_private_bucket(asset_bucket, region=region)
    if error is not None:
        print(f"  ERROR {error}", file=sys.stderr)
        return 1
    print(f"  ✓ {asset_bucket}")

    upload = subprocess.run(
        [str(UPLOAD_SCRIPT), "-y", region],
        cwd=str(DEPLOYMENT_DIR),
        text=True,
        env={
            **os.environ,
            "DIST_OUTPUT_BUCKET": base_bucket,
            "DIST_SOLUTION_NAME": config.get(
                "solutionName", "automated-security-response-on-aws"
            ),
            "DIST_VERSION": config.get("solutionVersion", ""),
        },
    )
    if upload.returncode != 0:
        print(f"ERROR: asset upload to {asset_bucket} failed", file=sys.stderr)
        return upload.returncode

    return _apply_member_stack(config, region)


_DOCUMENT_NAME_RE = re.compile(r'"Name"\s*:\s*"(ASR-[^"]+)"')


def _member_stack_document_names() -> frozenset[str]:
    """Every `ASR-*` document name the built member templates declare.

    Read from the build output rather than hard-coded: the member stack's shared
    remediation documents and each playbook's control runbooks are generated from
    source, and the list changes with every playbook or control added. Empty when
    there is no build, in which case the caller falls back to the prefix.
    """
    names: set[str] = set()
    templates = [
        GLOBAL_ASSETS_DIR / "automated-security-response-remediation-runbooks.template",
        *sorted((GLOBAL_ASSETS_DIR / "playbooks").glob("*MemberStack*.template")),
    ]
    for template in templates:
        if template.is_file():
            names.update(_DOCUMENT_NAME_RE.findall(template.read_text()))
    return frozenset(names)


def check_member_stack_collisions(account_id: str, *, region: str) -> list[str]:
    """Name every existing resource that would make a fresh member stack fail.

    CloudFormation's own `AWS::EarlyValidation::ResourceExistenceCheck` catches these,
    but it reports only "Validation failed with 2 error(s)" and points at an API that
    does not name them — so the operator is left with a `CREATE_FAILED` stack and no
    idea which resources are in the way.

    All of them are the member stack's fixed-name resources: the two that carry a
    Region but no namespace survive a failed stack's deletion, and the SSM documents
    carry neither, so a previous deployment's leftovers block the next one.
    """
    single = (
        _bucket_collision(account_id, region=region),
        _policy_collision(region=region),
        _document_collision(region=region),
    )
    return [item for item in single if item is not None] + _stuck_stack_collisions(
        region=region
    )


def _bucket_collision(account_id: str, *, region: str) -> str | None:
    bucket = f"so0111-asr-remediation-{region}-{account_id}"
    # The bucket lives in the member Region, which during deploy-member is not the
    # caller's default Region; without --region a cross-Region head-bucket can come
    # back as a redirect (non-zero) and the collision would be missed.
    probe = _run(
        ["aws", "s3api", "head-bucket", "--bucket", bucket, "--region", region],
        check=False,
    )
    return f"S3 bucket {bucket}" if probe.returncode == 0 else None


def _policy_collision(*, region: str) -> str | None:
    policy_name = f"ASR-RemediationConfigBucketAccess-{region}"
    policy = _run(
        [
            "aws",
            "iam",
            "list-policies",
            "--scope",
            "Local",
            "--query",
            f"Policies[?PolicyName=='{policy_name}'].Arn",
            "--output",
            "text",
        ],
        check=False,
    )
    if policy.returncode == 0 and policy.stdout.strip():
        return f"IAM managed policy {policy_name}"
    return None


def _document_collision(*, region: str) -> str | None:
    documents = _run(
        [
            "aws",
            "ssm",
            "list-documents",
            "--region",
            region,
            "--filters",
            "Key=Owner,Values=Self",
            "--query",
            "DocumentIdentifiers[?starts_with(Name, `ASR-`)].Name",
            "--output",
            "text",
        ],
        check=False,
    )
    if documents.returncode != 0 or not documents.stdout.strip():
        return None
    existing = set(documents.stdout.split())
    # Only the names the member stack itself creates collide. Custom runbooks
    # authored with this skill share the `ASR-` prefix (ASR-<Shortname>_<Version>_
    # <ControlId>) but are not the stack's, so blaming every ASR-* document refused
    # a legitimate deployment into any Region that had one.
    expected = _member_stack_document_names()
    blocking = sorted(existing & expected) if expected else sorted(existing)
    if not blocking:
        return None
    shown = ", ".join(blocking[:5]) + (", …" if len(blocking) > 5 else "")
    return f"{len(blocking)} SSM documents the member stack creates ({shown})"


def _stuck_stack_collisions(*, region: str) -> list[str]:
    # An empty SSM listing is not enough. A DELETE_FAILED stack keeps its
    # `AWS::SSM::Document` resources at UPDATE_COMPLETE even after the documents
    # themselves are deleted, and CloudFormation still refuses to let another stack
    # create those names — "already exists in stack <arn>". Deleting the documents
    # makes the document probe look clean while the create still fails, so the
    # stack itself has to be reported.
    stuck = _run(
        [
            "aws",
            "cloudformation",
            "describe-stacks",
            "--region",
            region,
            "--query",
            "Stacks[?StackStatus=='DELETE_FAILED' && starts_with(StackName, 'ASR')].StackName",
            "--output",
            "text",
        ],
        check=False,
    )
    if stuck.returncode != 0 or not stuck.stdout.strip():
        return []
    return [
        f"DELETE_FAILED stack {stack_name} (still claims its document names)"
        for stack_name in stuck.stdout.split()
    ]


def _stuck_stack_refusal(stack_name: str, *, region: str, status: str | None) -> str:
    """Refusal for a stack that exists but cannot be updated, with the way out."""
    return (
        f"REFUSED: {stack_name} in {region} is {status}. CloudFormation will not "
        f"update a stack in that state; delete it and rerun:\n"
        f"  aws cloudformation delete-stack --stack-name {stack_name} --region {region}\n"
        f"  aws cloudformation wait stack-delete-complete "
        f"--stack-name {stack_name} --region {region}\n"
        "  A DELETE_FAILED result means a resource is still held — see "
        "references/deployment-topology.md."
    )


def _collision_refusal(stack_name: str, *, region: str, collisions: list[str]) -> str:
    """The operator-facing refusal naming each resource a fresh member stack would hit."""
    return (
        f"REFUSED: {region} already holds member-stack resources that a new "
        f"{stack_name} would have to create:\n"
        + "".join(f"  - {item}\n" for item in collisions)
        + "  These names carry no namespace, so one member deployment per "
        "account+Region is the limit. Remove them (or delete the deployment "
        "that owns them) before retrying — see "
        "references/deployment-topology.md."
    )


def _apply_member_stack(config: LocalConfig, region: str) -> int:
    """Create or update `ASR-Member-<namespace>` in `region` and wait for it."""
    namespace = config.get("namespace", "")
    stack_name = f"ASR-Member-{namespace}"
    # The reference bucket is Region-agnostic and the template resolves its own
    # assets as `<base>-${AWS::Region}`, so one template serves every Region.
    template_url = (
        f"https://{config.get('templateBucketName', '')}.s3."
        f"{config.get('region', 'us-east-1')}.amazonaws.com/"
        f"{config.get('solutionName', '')}/{config.get('solutionVersion', '')}/"
        f"{MEMBER_TEMPLATE_FILE}"
    )

    parameters = [
        f"ParameterKey={key},ParameterValue={value}"
        for key, value in (
            *MEMBER_PLAYBOOK_PARAMETERS,
            ("LogGroupName", f"asr-log-group-{namespace}"),
            ("Namespace", namespace),
            (
                "SecHubAdminAccount",
                str(config.get("secHubAdminAccount", config.get("accountId", ""))),
            ),
        )
    ]

    status = _describe_stack_status(stack_name, region=region)
    if status in NON_UPDATABLE_STACK_STATUSES:
        # A create with --disable-rollback that failed still *exists*, so it would
        # otherwise be taken for an update — which CloudFormation then rejects, and
        # the operator is left able to neither create nor update.
        print(
            _stuck_stack_refusal(stack_name, region=region, status=status),
            file=sys.stderr,
        )
        return 1
    is_update = status is not None
    verb = "update" if is_update else "create"

    if not is_update:
        # Re-checked here, after the upload, so a resource created in the meantime is
        # still caught before CloudFormation fails the create with no names attached.
        collisions = check_member_stack_collisions(
            str(config.get("accountId", "")), region=region
        )
        if collisions:
            print(
                _collision_refusal(stack_name, region=region, collisions=collisions),
                file=sys.stderr,
            )
            return 1
    command = [
        "aws",
        "cloudformation",
        f"{verb}-stack",
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        "--stack-name",
        stack_name,
        "--template-url",
        template_url,
        "--region",
        region,
        "--parameters",
        *parameters,
    ]
    if not is_update:
        # Matches deploy-dev.sh: a failed create keeps its resources so the failure
        # can be read off the stack instead of being rolled back out of existence.
        command.append("--disable-rollback")

    print(f"{'Updating' if is_update else 'Creating'} {stack_name} in {region}...")
    result = _run(command, check=False)
    if result.returncode != 0:
        if "No updates are to be performed" in result.stderr:
            print(f"No updates for {stack_name}, skipping.")
            return 0
        print(f"ERROR: {result.stderr.strip()}", file=sys.stderr)
        return 1

    print(f"Waiting for {stack_name}...")
    wait = _run(
        [
            "aws",
            "cloudformation",
            "wait",
            f"stack-{verb}-complete",
            "--stack-name",
            stack_name,
            "--region",
            region,
        ],
        check=False,
    )
    try:
        outcome = _describe_stack_status(stack_name, region=region) or "gone"
    except StackStatusUnavailable as exc:
        outcome = f"status unavailable: {exc}"
    if wait.returncode != 0:
        print(f"ERROR: {stack_name} did not complete ({outcome})", file=sys.stderr)
        return 1
    print(f"✓ {stack_name}: {outcome}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    """Delete all stacks."""
    config = _read_config()
    if config is None:
        print("No local-config.json found. Nothing to delete.")
        return 0

    is_safe, msg = _verify_non_production(str(config.get("accountId", "")))
    if not is_safe:
        print(f"REFUSED: {msg}", file=sys.stderr)
        return 1

    print(f"Deleting stacks in account {config.get('accountId')}...")
    result = subprocess.run([str(DEPLOY_SCRIPT), "delete"], cwd=str(DEV_DIR), text=True)
    return result.returncode


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="deploy_stack.py",
        description="Deploy or manage ASR dev stacks (non-interactive).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    status_parser = subparsers.add_parser(
        "status", help="Check if stacks exist and report state"
    )
    status_parser.add_argument(
        "--region",
        # argparse applies `type` to a string default too, so the "use the config
        # Region" sentinel is None rather than an empty string.
        default=None,
        type=_region_arg,
        help="Region to report on (default: the one in local-config.json)",
    )

    # init
    init_parser = subparsers.add_parser(
        "init", help="First-time setup: create config + S3 buckets"
    )
    init_parser.add_argument("--account-id", required=True, help="AWS account ID")
    init_parser.add_argument(
        "--region",
        default="us-east-1",
        type=_region_arg,
        help="AWS region (default: us-east-1)",
    )
    init_parser.add_argument(
        "--email", required=True, help="Admin user email for WebUI Cognito"
    )
    init_parser.add_argument(
        "--sechub-admin",
        default="",
        help="Security Hub admin account (default: same as account-id)",
    )
    init_parser.add_argument(
        "--version", default="v4.0.0.dev", help="Solution version (default: v4.0.0.dev)"
    )

    # deploy
    deploy_parser = subparsers.add_parser("deploy", help="Build and deploy all stacks")
    deploy_parser.add_argument(
        "action",
        nargs="?",
        default="",
        # Mirrors deploy-dev.sh's own `case` arms, short forms included, so a
        # typo is rejected here instead of reaching the script — which would
        # otherwise cost an STS call and a "this will take 10-20 minutes"
        # message before the shell's usage error. `""` is listed because
        # `nargs="?"` checks the default against `choices` too.
        choices=["", "create", "c", "update", "u", "delete", "d"],
        help="create, update, or delete (auto-detects if empty)",
    )

    # deploy-member
    deploy_member_parser = subparsers.add_parser(
        "deploy-member",
        help="Create or update only the member stack, in an additional Region",
    )
    deploy_member_parser.add_argument(
        "--region",
        required=True,
        type=_region_arg,
        help="Region to deploy the member stack into (not the config Region)",
    )

    # delete
    subparsers.add_parser("delete", help="Delete all stacks")

    args = parser.parse_args(argv)

    commands = {
        "status": cmd_status,
        "init": cmd_init,
        "deploy": cmd_deploy,
        "deploy-member": cmd_deploy_member,
        "delete": cmd_delete,
    }
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
