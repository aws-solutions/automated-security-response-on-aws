#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# `${DEBUG:-}` rather than `$DEBUG`, so sourcing this script from a shell that
# already runs under `set -u` does not abort on an unset variable.
[[ ${DEBUG:-} ]] && set -x
set -eu -o pipefail

# Builds the open-source distribution that is published to the public GitHub
# repository.
#
# The archive is copied from the working tree, and the paths it may contain are
# listed explicitly in PUBLISHED_PATHS below. The path list is an allowlist: not
# everything in the repository is meant to be published, so a newly added
# top-level path is excluded by default. Publishing it takes a deliberate edit
# here.
#
# Because top-level paths default to unpublished, the risk shifts from leaking an
# internal file to silently omitting a public one. The assertions below are what
# make that trade safe: every allowlisted path must be represented in
# REQUIRED_FILES, so dropping or renaming one fails the build instead of shipping
# a quietly incomplete archive.
#
# `source/` and `deployment/` are published as whole trees, and in CI this script
# runs after build-s3-dist.sh, so those trees hold dependencies and build output
# by the time we copy them. PRUNED_NAMES is what keeps that out; the checks in
# assert_archive_contents fail the build if something gets past it.
#
# Documentation is internal by default: only `docs/published/` is published. Paths
# are published as they are tracked, so a link that resolves internally resolves
# in the public repository too. See docs/README.md.

# Paths published to the public repository. Keep this list minimal and
# deliberate — everything else in the repository stays internal.
PUBLISHED_PATHS=(
    .github
    .gitignore
    CHANGELOG.md
    CODE_OF_CONDUCT.md
    CONTRIBUTING.md
    LICENSE.txt
    NOTICE.txt
    README.md
    SECURITY.md
    deployment
    docs/published
    mypy.ini
    pyproject.toml
    simtest
    solution-manifest.yaml
    sonar-project.properties
    source
    test-stack
    tox.ini
)

# Files inside published paths that must not be published.
EXCLUDED_PATHS=(
    # Exercises the shell logic in the internal buildspec.yml, which is not published.
    source/test/buildspec.test.ts
    source/test/customBuildDeployedPaths.test.ts
)

# Dependencies, build output and local developer state, pruned from the copy at
# any depth. Without this the allowlisted `source/` and `deployment/` trees would
# publish whatever a build left behind in them.
PRUNED_NAMES=(
    # Dependencies and compiler output
    node_modules
    dist
    cdk.out
    cjs
    esm
    __pycache__
    '*.egg-info'
    # Build output under deployment/, including the directory this script writes
    # into — the copy must not read the archive it is producing.
    open-source
    global-s3-assets
    regional-s3-assets
    temp
    setenv.sh
    requirements.txt
    # Test and coverage output. `.coverage` is the pytest data file; the tracked
    # `.coveragerc` config files do not match it.
    coverage
    coverage-reports
    .pytest_cache
    .coverage
    .venv
    requirements_dev.txt
    # Editor and local state
    .DS_Store
    .idea
    .vscode
    .security-scan
    .temp_redpencil
    aws-exports.json
    bom.json
    dynamodb-local-metadata.json
    local-config.json
)

# One file per entry in PUBLISHED_PATHS, asserted present in the built archive.
# Guards against an allowlist entry being dropped or renamed, which would
# otherwise ship a silently incomplete archive. check_allowlist_is_covered
# enforces that every published path is represented here.
REQUIRED_FILES=(
    .github/PULL_REQUEST_TEMPLATE.md
    .gitignore
    CHANGELOG.md
    CODE_OF_CONDUCT.md
    CONTRIBUTING.md
    LICENSE.txt
    NOTICE.txt
    README.md
    SECURITY.md
    deployment/build-s3-dist.sh
    docs/published/automated-security-response-on-aws-architecture-diagram.png
    mypy.ini
    pyproject.toml
    simtest/simulate.py
    solution-manifest.yaml
    sonar-project.properties
    source/package.json
    test-stack/deploy-test-stack.sh
    tox.ini
)

# Paths that must never appear in the archive, matched against any path segment
# rather than only the repository root. `source/` and `deployment/` are published
# as whole trees, so anything added deep inside one of them is the remaining way a
# leak can happen — anchoring these to the root would only re-check what the
# allowlist already excludes by construction.
FORBIDDEN_PATTERNS=(
    # Internal tooling
    '(^|/)\.claude/'
    '(^|/)\.kiro/'
    '(^|/)\.nightswatch/'
    '(^|/)ai-assets/'
    '(^|/)build-tools/'
    '(^|/)AGENTS\.md$'
    '(^|/)AUTOSDE\.yaml$'
    '(^|/)AWSSD-'
    '(^|/)CLAUDE\.md$'
    '(^|/)Config$'
    '(^|/)buildspec\.yml$'
    '(^|/)loadtests($|/)'
    '(^|/)pre-cr'
    '(^|/)redpencil-suppressions\.json$'
    # Build output that PRUNED_NAMES is expected to have removed
    '(^|/)node_modules($|/)'
    '(^|/)cdk\.out($|/)'
    '(^|/)coverage($|/)'
    '(^|/)dist($|/)'
    '(^|/)__pycache__($|/)'
)

# Set by main so the EXIT trap can remove a partially staged archive, including
# one left behind by a failed validation.
staging_dir_to_clean=""

main() {
    local root_dir=$(dirname "$(cd -P -- "$(dirname "$0")" && pwd -P)")
    local deployment_dir="$root_dir"/deployment
    local open_source_dist_dir="$deployment_dir"/open-source
    local solution_trademarkedname="automated-security-response-on-aws"
    local staging_dir="$open_source_dist_dir"/staging

    cd "$root_dir"

    check_allowlist_is_covered
    check_published_paths_exist

    staging_dir_to_clean="$staging_dir"
    trap 'rm -rf "$staging_dir_to_clean"' EXIT

    rm -rf "$open_source_dist_dir"
    mkdir -p "$staging_dir"

    copy_published_paths "$staging_dir"
    prune_compiled_typescript "$staging_dir"

    assert_archive_contents "$staging_dir"

    ( cd "$staging_dir" && zip -q -r9 "$open_source_dist_dir"/"$solution_trademarkedname" . )
}

# Copies the allowlisted paths into the staging directory. Piping tar to tar
# prunes as it reads, so the ~870MB of node_modules under source/ is never copied.
copy_published_paths() {
    local staging_dir="$1"
    local exclude_args=() name path

    for name in "${PRUNED_NAMES[@]}"; do
        exclude_args+=(--exclude="$name")
    done
    for path in "${EXCLUDED_PATHS[@]}"; do
        exclude_args+=(--exclude="$path")
    done

    tar -c "${exclude_args[@]}" -- "${PUBLISHED_PATHS[@]}" | tar -x -C "$staging_dir"
}

# tsc writes JavaScript next to its TypeScript source where outDir is unset (see
# source/lambdas/tsconfig.json), so a built working tree carries compiled output
# inside the published tree.
#
# Declarations and source maps are only ever generated, so they go unconditionally.
# A .js can be either generated or hand-written — deployment/utils/*.js and
# source/lib/member/cloud-trail-event-processor/event-processor.js are published on
# purpose — so a .js is removed only when a same-named .ts sits beside it, which is
# what makes it tsc output. No published .js has a .ts of the same name.
prune_compiled_typescript() {
    local staging_dir="$1"
    local typescript_file

    find "$staging_dir" -type f \( -name '*.d.ts' -o -name '*.d.ts.map' -o -name '*.js.map' \) -delete

    while IFS= read -r typescript_file; do
        rm -f "${typescript_file%.ts}".js
    done < <(find "$staging_dir" -type f -name '*.ts' ! -name '*.d.ts')
}

# Every published path must have a required file under it, so that dropping a
# path from the allowlist fails the build rather than silently shipping less.
check_allowlist_is_covered() {
    local published required is_covered failed=0

    for published in "${PUBLISHED_PATHS[@]}"; do
        is_covered=0
        for required in "${REQUIRED_FILES[@]}"; do
            if [[ "$required" == "$published" || "$required" == "$published"/* ]]; then
                is_covered=1
                break
            fi
        done
        if (( ! is_covered )); then
            printf 'ERROR: published path has no entry in REQUIRED_FILES: %s\n' "$published" >&2
            printf '       Add a file from that path so its omission would fail the build.\n' >&2
            failed=1
        fi
    done

    return "$failed"
}

# tar fails on a missing operand, but reports it as one line among its own output.
# Name the path that is actually gone instead.
check_published_paths_exist() {
    local published failed=0

    for published in "${PUBLISHED_PATHS[@]}"; do
        if [[ ! -e "$published" ]]; then
            printf 'ERROR: allowlisted path does not exist: %s\n' "$published" >&2
            failed=1
        fi
    done

    if (( failed )); then
        printf '       Remove it from PUBLISHED_PATHS, or run from the repository root.\n' >&2
    fi

    return "$failed"
}

# Fails the build if the staged archive is missing a required file or contains a
# path that must stay internal.
assert_archive_contents() {
    local staging_dir="$1"
    local failed=0

    check_required_files_present "$staging_dir" || failed=1
    check_excluded_paths_absent "$staging_dir" || failed=1
    check_no_internal_paths "$staging_dir" || failed=1
    check_docs_are_internal_by_default "$staging_dir" || failed=1

    if (( failed )); then
        printf 'ERROR: open-source archive failed validation; nothing was published.\n' >&2
        return 1
    fi
}

check_required_files_present() {
    local staging_dir="$1"
    local file failed=0

    for file in "${REQUIRED_FILES[@]}"; do
        if [[ ! -e "$staging_dir/$file" ]]; then
            printf 'ERROR: required file missing from open-source archive: %s\n' "$file" >&2
            failed=1
        fi
    done

    return "$failed"
}

check_excluded_paths_absent() {
    local staging_dir="$1"
    local path failed=0

    for path in "${EXCLUDED_PATHS[@]}"; do
        if [[ -e "$staging_dir/$path" ]]; then
            printf 'ERROR: excluded path present in open-source archive: %s\n' "$path" >&2
            failed=1
        fi
    done

    return "$failed"
}

check_no_internal_paths() {
    local staging_dir="$1"
    local pattern offenders offender_count staged_paths failed=0

    staged_paths=$(cd "$staging_dir" && find . -mindepth 1 | sed 's|^\./||')

    for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
        offenders=$(printf '%s\n' "$staged_paths" | grep -E "$pattern" || true)
        if [[ -n "$offenders" ]]; then
            # A leaked dependency tree is tens of thousands of paths; the first
            # few are enough to identify it.
            offender_count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
            printf 'ERROR: internal path present in open-source archive (%s match(es) for %s):\n%s\n' \
                "$offender_count" "$pattern" "$(printf '%s\n' "$offenders" | head -5)" >&2
            failed=1
        fi
    done

    return "$failed"
}

# Documentation is published only by moving it into docs/published/. Anything else
# under docs/ means the allowlist grew a path that bypasses that rule.
check_docs_are_internal_by_default() {
    local staging_dir="$1"
    local unexpected

    unexpected=$(cd "$staging_dir" && find docs -mindepth 1 -maxdepth 1 ! -name published 2>/dev/null || true)
    if [[ -n "$unexpected" ]]; then
        printf 'ERROR: only docs/published/ may be published, but the archive contains:\n%s\n' "$unexpected" >&2
        printf '       Move the file into docs/published/ to publish it deliberately.\n' >&2
        return 1
    fi
}

# Run the build only when executed. Sourcing the script instead loads the path
# lists and the check functions without building anything, which is how
# source/test/openSourceDistAllowlist.test.ts exercises the checks directly
# rather than by running a whole build per case.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
