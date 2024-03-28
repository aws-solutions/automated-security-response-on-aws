#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
[[ $DEBUG ]] && set -x
set -eu -o pipefail

main() {
    local root_dir=$(dirname "$(cd -P -- "$(dirname "$0")" && pwd -P)")
    local deployment_dir="$root_dir"/deployment
    local open_source_dist_dir="$deployment_dir"/open-source
    local solution_trademarkedname="automated-security-response-on-aws"

    rm -rf "$open_source_dist_dir"
    mkdir -p "$open_source_dist_dir"

    pushd "$root_dir"
    zip -q -r9 "$open_source_dist_dir"/"$solution_trademarkedname" . \
        -x ".git/*" \
        -x "*/node_modules/*" \
        -x "*/dist/*" \
        -x "*/cdk.out/*" \
        -x "*/.venv/*" \
        -x "*/__pycache__/*" \
        -x "*/coverage/*" \
        -x "*/.pytest_cache/*" \
        -x "*/.coverage" \
        -x "deployment/global-s3-assets/*" \
        -x "deployment/open-source/*" \
        -x "deployment/regional-s3-assets/*" \
        -x "deployment/temp/*" \
        -x "deployment/test/*" \
        -x ".viperlightrc.*" \
        -x "codescan-*.sh"
    popd
}

main "$@"
