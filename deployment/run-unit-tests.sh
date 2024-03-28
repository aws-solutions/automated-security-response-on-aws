#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
[[ "$DEBUG" ]] && set -x
set -eo pipefail

maxrc=0
rc=0
export overrideWarningsEnabled=false

[[ $1 == 'update' ]] && {
    update="true"
    echo "UPDATE MODE: CDK Snapshots will be updated. CDK UNIT TESTS WILL BE SKIPPED"
} || update="false"

[[ ! -d .venv ]] && python3 -m venv .venv
source ./.venv/bin/activate
python3 -m pip install -U pip setuptools

echo 'Installing required Python testing modules'
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
    python3 -m pytest --cov --cov-report=term-missing --cov-report "xml:$report_file"
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

if [[ -e './solution_env.sh' ]]; then
    chmod +x ./solution_env.sh
    source ./solution_env.sh
else
    echo "solution_env.sh is missing from the solution root."
    exit 1
fi

if [[ -z "$SOLUTION_ID" ]]; then
    echo "SOLUTION_ID is missing from ../solution_env.sh"
    exit 1
else
    export SOLUTION_ID
fi

if [[ -z "$SOLUTION_NAME" ]]; then
    echo "SOLUTION_NAME is missing from ../solution_env.sh"
    exit 1
else
    export SOLUTION_NAME
fi

if [[ -z "$SOLUTION_TRADEMARKEDNAME" ]]; then
    echo "SOLUTION_TRADEMARKEDNAME is missing from ../solution_env.sh"
    exit 1
else
    export SOLUTION_TRADEMARKEDNAME
fi

echo "------------------------------------------------------------------------------"
echo "[Lint] Code Style and Lint"
echo "------------------------------------------------------------------------------"
cd $source_dir
npx prettier --check '**/*.ts'
npx eslint --ext .ts --max-warnings=0 .
cd ..
tox -e format
tox -e lint

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
echo "[Test] Python Unit Tests - Orchestrator Lambdas"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/Orchestrator" "Orchestrator"

echo "------------------------------------------------------------------------------"
echo "[Test] Python Unit Tests - SolutionDeploy"
echo "------------------------------------------------------------------------------"
run_pytest "${source_dir}/solution_deploy/source" "SolutionDeploy"

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
for playbook in `ls ${source_dir}/playbooks`; do
    if [ -d ${source_dir}/playbooks/${playbook}/ssmdocs/scripts/tests ]; then
        run_pytest "${source_dir}/playbooks/${playbook}/ssmdocs/scripts" "Playbook${playbook}"
    fi
done

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
