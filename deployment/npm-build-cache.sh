#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Idempotency guards for npm installs and TypeScript builds that more than one
# build script performs.
#
# buildspec.yml runs build-s3-dist.sh and then run-unit-tests.sh in the same
# CodeBuild job. Both scripts install the webui dependencies and build the
# data-models package, so the second script repeats work the first one already
# finished. These functions make the repeated invocation a no-op while keeping
# each script correct when run on its own from a clean checkout.
#
# Staleness is always resolved in the safe direction: anything that cannot be
# proven current is rebuilt or reinstalled.
#
# Usage:
#   source npm-build-cache.sh
#   install_npm_dependencies_if_stale <package_dir>
#   build_npm_package_if_stale <package_dir> <build_output> <npm_script>

# Runs `npm install` in a package directory unless the installed tree already
# matches the manifests.
#
# npm records the tree it installed in node_modules/.package-lock.json. If that
# marker is present and neither package-lock.json nor package.json has been
# modified since, the existing node_modules is current.
install_npm_dependencies_if_stale() {
    local package_dir="$1"
    local installed_marker="$package_dir/node_modules/.package-lock.json"

    if [[ -f "$installed_marker" ]] &&
        [[ ! "$package_dir/package-lock.json" -nt "$installed_marker" ]] &&
        [[ ! "$package_dir/package.json" -nt "$installed_marker" ]]; then
        echo "Dependencies in $package_dir are current, skipping npm install"
        return 0
    fi

    echo "Installing dependencies in $package_dir"
    (cd "$package_dir" && npm install)
}

# Runs an npm build script in a package directory unless the build output is
# newer than every input that feeds it.
#
# Inputs are the package's TypeScript sources plus its manifests and tsconfigs,
# excluding node_modules and previously generated output.
build_npm_package_if_stale() {
    local package_dir="$1"
    local build_output="$2"
    local npm_script="$3"

    if [[ -f "$build_output" ]]; then
        local newer_input
        newer_input=$(find "$package_dir" \
            \( -name node_modules -o -name cjs -o -name esm \) -prune -o \
            -type f \( -name '*.ts' -o -name 'tsconfig*.json' -o -name 'package.json' \) \
            -newer "$build_output" -print -quit)

        if [[ -z "$newer_input" ]]; then
            echo "Build output $build_output is current, skipping npm run $npm_script"
            return 0
        fi
    fi

    echo "Building $package_dir (npm run $npm_script)"
    (cd "$package_dir" && npm run "$npm_script")
}
