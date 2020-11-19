#!/bin/bash
#
# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./run-unit-tests.sh
#
maxrc=0
rc=0
export overrideWarningsEnabled=false

[[ $1 == 'update' ]] && {
    update="true" 
    echo "UPDATE MODE: CDK Snapshots will be updated. CDK UNIT TESTS WILL BE SKIPPED"
} || update="false"

#!/bin/bash
echo 'Installing required Python testing modules'
pip install -r ./testing_requirements.txt

# Get reference for all important folders
template_dir="$PWD"
source_dir="$template_dir/../source"
temp_source_dir="$template_dir/temp/source"

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

# Snapshot-only Test
echo "------------------------------------------------------------------------------"
echo "[Test] CDK Unit Tests - playbook CIS"
echo "------------------------------------------------------------------------------"
cd $temp_source_dir/playbooks/CIS
[[ $update == "true" ]] && {
    npm run test -- -u
    cp -f test/__snapshots__/* $source_dir/playbooks/CIS/test/__snapshots__/
} || {
    npm run test
    rc=$?
    echo CDK Unit Tests RC=$rc
    if [ "$rc" -gt "$maxrc" ]; then
        maxrc=$rc
    fi
}

echo "------------------------------------------------------------------------------"
echo "[Test] CDK Unit Tests - core"
echo "------------------------------------------------------------------------------"
cd $temp_source_dir/playbooks/core
npm run test
rc=$?
echo CDK Unit Tests RC=$rc
if [ "$rc" -gt "$maxrc" ]; then
	maxrc=$rc
fi

# Snapshot-only Test
echo "------------------------------------------------------------------------------"
echo "[Test] CDK Unit Tests - solution_deploy"
echo "------------------------------------------------------------------------------"
cd $temp_source_dir/solution_deploy
[[ $update == "true" ]] && {
    npm run test -- -u
    cp -f test/__snapshots__/* $source_dir/solution_deploy/test/__snapshots__/
} || {
    npm run test
    rc=$?
    echo CDK Unit Tests RC=$rc
    if [ "$rc" -gt "$maxrc" ]; then
    	maxrc=$rc
    fi
}

echo "------------------------------------------------------------------------------"
echo "[Test] Python Unit Tests"
echo "------------------------------------------------------------------------------"
cd ${template_dir}/build/playbooks/CIS
ls tests
pytest
rc=$?
if [ "$rc" -gt "$maxrc" ]; then
	maxrc=$rc
fi

if [ "$maxrc" -ne "0" ]; then
	echo "** UNIT TESTS FAILED **"
else
	echo "Unit Tests Successful"
fi
exit $maxrc
