#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
[[ "$DEBUG" ]] && set -x
set -eo pipefail

source "$(cd -P -- "$(dirname "$0")" && pwd -P)"/npm-build-cache.sh

maxrc=0
rc=0
export overrideWarningsEnabled=false

[[ $1 == 'update' ]] && {
    update="true"
    echo "UPDATE MODE: CDK Snapshots will be updated. CDK unit tests will run with snapshot update mode (mismatches are updated rather than failing)"
} || update="false"

[[ $1 == 'snapshot' ]] && {
    echo "SNAPSHOT MODE: Updating CDK snapshots only, skipping all other tests"
    [[ ! -d .venv ]] && python3.11 -m venv .venv
    source ./.venv/bin/activate
    CDK_CONFIG_PATH="../source/cdk-config.json"
    export SOLUTION_ID=$(node -p "require('$CDK_CONFIG_PATH').solution.id")
    export SOLUTION_NAME=$(node -p "require('$CDK_CONFIG_PATH').solution.trademarkedName")
    export SOLUTION_TRADEMARKEDNAME=$(node -p "require('$CDK_CONFIG_PATH').solution.trademarkedName")
    export SOLUTION_DISPLAY_NAME=$(node -p "require('$CDK_CONFIG_PATH').solution.name")
    cd ../source
    npm run build
    npx jest -u
    exit $?
}

[[ $1 == 'format' ]] && {
    [[ ! -d .venv ]] && python3.11 -m venv .venv
    source ./.venv/bin/activate
    python3.11 -m pip install -U pip setuptools -q
    "$( command -v poetry || echo "${POETRY_HOME}/bin/poetry" )" export --with dev -f requirements.txt --output requirements_dev.txt --without-hashes
    pip install -r ./requirements_dev.txt -q
    cd ..
    tox -e format
    tox -e lint
    exit $?
}

[[ ! -d .venv ]] && python3.11 -m venv .venv
source ./.venv/bin/activate
python3.11 -m pip install -U pip setuptools

echo 'Installing required Python testing modules'
if command -v poetry >/dev/null 2>&1; then
        POETRY_COMMAND="poetry"
      elif [ -n "$POETRY_HOME" ] && [ -x "$POETRY_HOME/bin/poetry" ]; then
        POETRY_COMMAND="$POETRY_HOME/bin/poetry"
      else
        echo "Poetry is not available. Aborting script." >&2
        exit 1
      fi
"$POETRY_COMMAND" export --with dev -f requirements.txt --output requirements_dev.txt --without-hashes
pip install -r ./requirements_dev.txt

cd ..
pip install -e .
cd ./deployment

# Get reference for all important folders
template_dir="$PWD"
cd ../source
source_dir="$PWD"
cd ${template_dir}
temp_source_dir="$template_dir/temp/source"
coverage_report_path="${template_dir}/test/coverage-reports"
mkdir -p ${coverage_report_path}

run_pytest() {
    cd ${1}
    report_file="${coverage_report_path}/${2}.coverage.xml"
    echo "coverage report path set to ${report_file}"

    # Use -vv for debugging
    python3.11 -m pytest --cov --cov-report=term-missing --cov-report "xml:$report_file"
    rc=$?

    if [ "$rc" -ne "0" ]; then
        echo "** UNIT TESTS FAILED **"
    else
        echo "Unit Tests Successful"
    fi
    if [ "$rc" -gt "$maxrc" ]; then
        maxrc=$rc
    fi
}

# Load solution configuration from cdk-config.json (single source of truth)
CDK_CONFIG_PATH="${source_dir}/cdk-config.json"
if [[ ! -e "$CDK_CONFIG_PATH" ]]; then
    echo "ERROR: cdk-config.json not found at $CDK_CONFIG_PATH"
    echo "This file is required for builds. Ensure the file exists in source/ directory."
    exit 1
fi

# Read solution info from cdk-config.json using Node.js (already required for CDK)
export SOLUTION_ID=$(node -p "require('$CDK_CONFIG_PATH').solution.id")
export SOLUTION_NAME=$(node -p "require('$CDK_CONFIG_PATH').solution.trademarkedName")
export SOLUTION_TRADEMARKEDNAME=$(node -p "require('$CDK_CONFIG_PATH').solution.trademarkedName")
export SOLUTION_DISPLAY_NAME=$(node -p "require('$CDK_CONFIG_PATH').solution.name")

if [[ -z "$SOLUTION_ID" ]] || [[ "$SOLUTION_ID" == "null" ]]; then
    echo "ERROR: solution.id is missing from cdk-config.json"
    exit 1
fi

if [[ -z "$SOLUTION_NAME" ]] || [[ "$SOLUTION_NAME" == "null" ]]; then
    echo "ERROR: solution.trademarkedName is missing from cdk-config.json"
    exit 1
fi

if [[ -z "$SOLUTION_TRADEMARKEDNAME" ]] || [[ "$SOLUTION_TRADEMARKEDNAME" == "null" ]]; then
    echo "ERROR: solution.trademarkedName is missing from cdk-config.json"
    exit 1
fi

echo "Loaded configuration from cdk-config.json:"
echo "  SOLUTION_ID: $SOLUTION_ID"
echo "  SOLUTION_NAME: $SOLUTION_NAME"
echo "  SOLUTION_DISPLAY_NAME: $SOLUTION_DISPLAY_NAME"
echo "  SOLUTION_TRADEMARKEDNAME: $SOLUTION_TRADEMARKEDNAME"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Unit Tests - Orchestrator Lambdas"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/Orchestrator" "Orchestrator"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Unit Tests - SolutionDeploy"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/solution_deploy/source" "SolutionDeploy"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Unit Tests - Blueprints"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/blueprints/jira" "Jira Blueprint"
run_pytest "${source_dir}/blueprints/servicenow" "ServiceNow Blueprint"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Unit Tests - LambdaLayers"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/layer" "LambdaLayers"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Scripts for Remediation Runbooks"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/remediation_runbooks/scripts" "RemediationRunbooks"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Scripts for Playbook common scripts"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/playbooks/common" "PlaybookCommon"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Scripts for Playbooks"
echo "------------------------------------------------------------------------------"
# Playbooks are inconsistent about the directory name, so accept either. AFSBP and
# PCI321 use "test" while SC uses "tests"; checking only one name silently skips
# the others.
for playbook in `ls ${source_dir}/playbooks`; do
    if [ -d ${source_dir}/playbooks/${playbook}/ssmdocs/scripts/tests ] || [ -d ${source_dir}/playbooks/${playbook}/ssmdocs/scripts/test ]; then
        run_pytest "${source_dir}/playbooks/${playbook}/ssmdocs/scripts" "Playbook${playbook}"
    fi
done

echo "------------------------------------------------------------------------------"
echo "[Build] Data Models Package"
echo "------------------------------------------------------------------------------"
# build-s3-dist.sh builds this package too, and buildspec.yml runs it just before
# this script. Skip the rebuild when the output is already current; still builds
# from scratch when this script is run on its own.
build_npm_package_if_stale "$source_dir/data-models" "$source_dir/data-models/cjs/index.js" build
rc=$?
if [ "$rc" -ne "0" ]; then
    echo "** DATA MODELS BUILD FAILED **"
    exit $rc
fi

source "${template_dir}/dynamodb-local.sh"
ddb_local_start || exit 1
trap 'ddb_local_stop' EXIT

echo "------------------------------------------------------------------------------"
echo "[Test] Preprocessor Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/lambdas
npm run test:sequential:preprocessor

echo "------------------------------------------------------------------------------"
echo "[Test] Lambdas/common Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/lambdas
npm run test:sequential:common

echo "------------------------------------------------------------------------------"
echo "[Test] Findings synchronization Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/lambdas
npm run test:sequential:synchronization

echo "------------------------------------------------------------------------------"
echo "[Test] API Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/lambdas
npm run test:sequential:api

echo "------------------------------------------------------------------------------"
echo "[Test] Notification Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/lambdas
npm run test:sequential:notification

ddb_local_stop

echo "------------------------------------------------------------------------------"
echo "[Test] Deployment Utils Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$template_dir"/utils
npm run test

echo "------------------------------------------------------------------------------"
echo "[Synth] CDK Synthesis - Generate templates for size validation"
echo "------------------------------------------------------------------------------"
cd "$source_dir"
npm run build

# Synthesize solution_deploy templates
cd "$source_dir"/solution_deploy
npx cdk synth --quiet

# Synthesize playbook templates
for playbook in AFSBP CIS120 CIS140 CIS300 NIST80053 PCI321 SC; do
    if [ -d "${source_dir}/playbooks/${playbook}" ]; then
        cd "${source_dir}/playbooks/${playbook}"
        npx cdk synth --quiet
    fi
done

# Synthesize blueprint templates
for blueprint in jira servicenow; do
    if [ -d "${source_dir}/blueprints/${blueprint}/cdk" ]; then
        cd "${source_dir}/blueprints/${blueprint}/cdk"
        npx cdk synth --quiet
    fi
done

echo "------------------------------------------------------------------------------"
echo "[Test] CDK Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$source_dir"
[[ $update == "true" ]] && {
    npm run test -- -u
} || {
    npm run test
    rc=$?
    if [ "$rc" -ne "0" ]; then
        echo "** UNIT TESTS FAILED **"
    else
        echo "Unit Tests Successful"
    fi
    if [ "$rc" -gt "$maxrc" ]; then
        maxrc=$rc
    fi
}


echo "------------------------------------------------------------------------------"
echo "[Test] WebUI Unit Tests"
echo "------------------------------------------------------------------------------"
install_npm_dependencies_if_stale "$source_dir/webui"
cd $source_dir/webui
npm run test
rc=$?
if [ "$rc" -ne "0" ]; then
    echo "** WEBUI UNIT TESTS FAILED **"
else
    echo "WebUI Unit Tests Successful"
fi
if [ "$rc" -gt "$maxrc" ]; then
    maxrc=$rc
fi

echo "------------------------------------------------------------------------------"
echo "[Lint] Code Style and Lint"
echo "------------------------------------------------------------------------------"
cd $source_dir
npx eslint --fix --ext .ts --max-warnings=0 --ignore-pattern "*.d.ts" .
cd ..
tox -e format
tox -e lint


# The pytest --cov with its parameters and .coveragerc generates a xml cov-report with `coverage/sources` list
# with absolute path for the source directories. To avoid dependencies of tools (such as SonarQube) on different
# absolute paths for source directories, this substitution is used to convert each absolute source directory
# path to the corresponding project relative path.

coverage_report_path=${template_dir}/test/coverage-reports/*.xml
sed -i -e "s|<source>.*${source_dir}|<source>source|g" $coverage_report_path
sed -i -e "s|<source>.*${temp_source_dir}|<source>source|g" $coverage_report_path

echo "========================================================================="
if [ "$maxrc" -ne "0" ]; then
    echo "** UNIT TESTS FAILED **"
else
    echo "ALL UNIT TESTS PASSED"
fi

exit $maxrc
