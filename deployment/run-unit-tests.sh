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
for playbook in `ls ${source_dir}/playbooks`; do
    if [ -d ${source_dir}/playbooks/${playbook}/ssmdocs/scripts/tests ]; then
        run_pytest "${source_dir}/playbooks/${playbook}/ssmdocs/scripts" "Playbook${playbook}"
    fi
done

echo "------------------------------------------------------------------------------"
echo "[Build] Data Models Package"
echo "------------------------------------------------------------------------------"
cd "$source_dir"/data-models
npm run build
rc=$?
if [ "$rc" -ne "0" ]; then
    echo "** DATA MODELS BUILD FAILED **"
    exit $rc
fi

echo "------------------------------------------------------------------------------"
echo "[Setup] Starting DynamoDB Local"
echo "------------------------------------------------------------------------------"

# Check if DynamoDB Local is already running via Docker
if curl -s http://localhost:8000 >/dev/null 2>&1; then
    echo "DynamoDB Local is already running (likely via Docker)"
    DDB_PID=""
else
    # Fall back to tar-based installation
    if [[ -z "$DDB_LOCAL_HOME" ]]; then
        echo "ERROR: DDB_LOCAL_HOME environment variable is not set and DynamoDB Local is not running via Docker"
        exit 1
    fi

    # Verify DynamoDB Local files exist
    if [[ ! -f "$DDB_LOCAL_HOME/DynamoDBLocal.jar" ]]; then
        echo "ERROR: DynamoDBLocal.jar not found at $DDB_LOCAL_HOME/DynamoDBLocal.jar"
        exit 1
    fi

    if [[ ! -d "$DDB_LOCAL_HOME/DynamoDBLocal_lib" ]]; then
        echo "ERROR: DynamoDBLocal_lib directory not found at $DDB_LOCAL_HOME/DynamoDBLocal_lib"
        exit 1
    fi

    java -Djava.library.path="$DDB_LOCAL_HOME"/DynamoDBLocal_lib -jar "$DDB_LOCAL_HOME"/DynamoDBLocal.jar -sharedDb -inMemory >/dev/null 2>&1 &
    DDB_PID=$!

    # Wait for DynamoDB Local to be ready
    echo "Waiting for DynamoDB Local to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8000 >/dev/null 2>&1; then
            echo "DynamoDB Local is ready (attempt $i)"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "ERROR: DynamoDB Local failed to become ready after 30 seconds"
            kill $DDB_PID 2>/dev/null || true
            exit 1
        fi
        sleep 1
    done

    if ! kill -0 $DDB_PID 2>/dev/null; then
        echo "ERROR: DynamoDB Local failed to start"
        exit 1
    fi
    echo "DynamoDB Local started successfully (PID: $DDB_PID)"

    # Ensure DynamoDB process is killed on script exit
    trap 'kill $DDB_PID 2>/dev/null || true' EXIT
fi

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
echo "[Cleanup] Stopping DynamoDB Local"
echo "------------------------------------------------------------------------------"
if [[ -n "$DDB_PID" ]]; then
    kill $DDB_PID 2>/dev/null || true
else
    echo "DynamoDB Local was running via Docker (not stopped by this script)"
fi

echo "------------------------------------------------------------------------------"
echo "[Test] Deployment Utils Unit Tests"
echo "------------------------------------------------------------------------------"
cd "$template_dir"/utils
npm run test

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
cd $source_dir/webui
npm install
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
npx eslint --ext .ts --max-warnings=0 --ignore-pattern "*.d.ts" .
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
