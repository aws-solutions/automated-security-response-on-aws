#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

do_cmd () {
    echo "------ EXEC $*"
    $*
    rc=$?
    if [ $rc -gt 0 ]
    then
            echo "Aborted - rc=$rc"
            exit $rc
    fi
}
do_replace() {
    replace="s/$2/$3/g"
    file=$1
    do_cmd sed -i '' -e $replace $file
}

cleanup_ts() {
    echo ---- Clean up Typescript build files
    start_at=$1
    find $start_at -iname "*.d.ts" | while read file; do
        filename=`basename -s .d.ts $file`
        filedir=`dirname $file`
        do_cmd rm $filedir/$filename.d.ts
        do_cmd rm $filedir/$filename.js
    done
}

prune_dir() {
    target=$1
    if [ -z target ]; then
        echo ERROR!: no target specified for prune_dir!
        exit 128
    fi
    find $dist_dir -type d -iname $target | while read thisdir; do
        if [ -d $thisdir ]; then
            do_cmd rm -r $thisdir
        fi
    done
}
#------------------------------------------------------------------------------
# INITIALIZATION
#------------------------------------------------------------------------------
# solution_env.sh must exist in the solution root. It is the definitive source
# for solution ID, name, and trademarked name
# Ex:
# #!/bin/bash
# SOLUTION_ID='SO0111'
# SOLUTION_NAME='AWS Security Hub Automated Response & Remediation'
# SOLUTION_TRADEMARKEDNAME='aws-security-hub-automated-response-and-remediation'
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

# Get reference for all important folders
deploy_root="$PWD"
source_template_dir="${deploy_root}/global-s3-assets"
dist_dir="${deploy_root}/open-source"
dist_template_dir="$dist_dir/deployment"
source_dir="${deploy_root}/../source"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old open-source folder"
echo "------------------------------------------------------------------------------"
do_cmd rm -rf $dist_dir
do_cmd mkdir -p $dist_dir
do_cmd mkdir -p $dist_template_dir

echo "------------------------------------------------------------------------------"
echo "[Packing] Build Script"
echo "------------------------------------------------------------------------------"
echo "Copying files from /deployment"
do_cmd cp ${deploy_root}/build-s3-dist.sh $dist_template_dir
do_cmd cp ${deploy_root}/run-unit-tests.sh $dist_template_dir
do_cmd cp ${deploy_root}/solution_env.sh $dist_template_dir
do_cmd cp ${deploy_root}/testing_requirements.txt $dist_template_dir

echo "------------------------------------------------------------------------------"
echo "[Packing] Source Folder"
echo "------------------------------------------------------------------------------"
do_cmd cp -r $source_dir $dist_dir
do_cmd cp ${deploy_root}/../LICENSE.txt $dist_dir
do_cmd cp ${deploy_root}/../NOTICE.txt $dist_dir
do_cmd cp ${deploy_root}/../README.md $dist_dir
do_cmd cp ${deploy_root}/../CODE_OF_CONDUCT.md $dist_dir
do_cmd cp ${deploy_root}/../CONTRIBUTING.md $dist_dir
do_cmd cp ${deploy_root}/../CHANGELOG.md $dist_dir
do_cmd cp ${deploy_root}/../.gitignore $dist_dir
do_cmd cp -r ${deploy_root}/../.github $dist_dir

echo "------------------------------------------------------------------------------"
echo "[Packing] Clean dist, node_modules, and coverage folders"
echo "------------------------------------------------------------------------------"
find $dist_dir -iname "node_modules" -type d -exec rm -r "{}" \; 2> /dev/null
find $dist_dir -iname "dist" -type d -exec rm -r "{}" \; 2> /dev/null
find $dist_dir -type f -name 'package-lock.json' -delete
if [ -d $dist_dir/source/coverage ]; then
    echo ---- Remove Coverage reports
    do_cmd rm -rf $dist_dir/source/coverage
fi
cleanup_ts $dist_dir

deldirs=("idna*" "pytz*" "urllib*" "certifi*" "charset*" "requests*" "__pycache__" "normalizer" ".pytest_cache" "cdk.out")
echo ---- Clean up unwanted directories
for dir_to_delete in "${deldirs[@]}"
  do
    echo ----    $dir_to_delete
    prune_dir $dir_to_delete
  done

delfiles=(".coveragerc" ".DS_Store")
for file_to_delete in "${delfiles[@]}";
  do
    echo "---- Removing file: $file_to_delete everywhere"
    find $dist_dir -type f -name $file_to_delete | while read file
        do
            do_cmd rm $file
        done
  done

echo "------------------------------------------------------------------------------"
echo "[Packing] Create GitHub (open-source) zip file"
echo "------------------------------------------------------------------------------"
cd $dist_dir
do_cmd zip -q -r9 ../${SOLUTION_TRADEMARKEDNAME}.zip * .gitignore .github
echo "Clean up open-source folder"
do_cmd rm -rf *
do_cmd rm .gitignore
do_cmd rm -r .github
do_cmd mv ../${SOLUTION_TRADEMARKEDNAME}.zip .
echo "Completed building ${SOLUTION_TRADEMARKEDNAME}.zip dist"
