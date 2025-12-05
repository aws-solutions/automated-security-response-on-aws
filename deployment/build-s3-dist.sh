#!/usr/bin/env bash
#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
[[ $DEBUG ]] && set -x
set -eu -o pipefail

header() {
    declare text=$1
    echo "------------------------------------------------------------------------------"
    echo "$text"
    echo "------------------------------------------------------------------------------"
}

usage() {
    echo "Usage: $0 -b <bucket> [-v <version>] [-t]"
    echo "Version must be provided via a parameter or ../version.txt. Others are optional."
    echo "-t indicates this is a pre-prod build and instructs the build to use a non-prod Solution ID, DEV-SOxxxx"
    echo "Production example: ./build-s3-dist.sh -b solutions -v v1.0.0"
    echo "Dev example: ./build-s3-dist.sh -b solutions -v v1.0.0 -t"
}

clean() {
    declare clean_dirs=("$@")
    for dir in ${clean_dirs[@]}; do rm -rf "$dir"; done
}

# This assumes all of the OS-level configuration has been completed and git repo has already been cloned
#
# This script should be run from the repo's deployment directory
# cd deployment
# ./build-s3-dist.sh source-bucket-base-name solution-name version-code
#
# Paramenters:
#  - source-bucket-base-name: Name for the S3 bucket location where the template will source the Lambda
#    code from. The template will append '-[region_name]' to this bucket name.
#    For example: ./build-s3-dist.sh solutions v1.0.0
#    The template will then expect the source code to be located in the solutions-[region_name] bucket
#
#  - solution-name: name of the solution for consistency
#
#  - version-code: version of the package
main() {
    local root_dir=$(dirname "$(cd -P -- "$(dirname "$0")" && pwd -P)")
    local deployment_dir="$root_dir"/deployment
    local template_dist_dir="$deployment_dir"/global-s3-assets
    local build_dist_dir="$deployment_dir/"regional-s3-assets
    local source_dir="$root_dir"/source
    local temp_work_dir="${deployment_dir}"/temp
    local devtest=""

    local clean_dirs=("$template_dist_dir" "$build_dist_dir" "$temp_work_dir")

    while getopts ":b:v:tch" opt;
    do
        case "${opt}" in
            b) local bucket=${OPTARG};;
            v) local version=${OPTARG};;
            t) devtest=1;;
            c) clean "${clean_dirs[@]}" && exit 0;;
            *) usage && exit 0;;
        esac
    done

    if [[ -z "$version" ]]; then
        usage && exit 1
    fi

    # Prepend version with "v" if it does not already start with "v"
    if [[ $version != v* ]]; then
        version=v"$version"
    fi

    clean "${clean_dirs[@]}"

    # Save in environmental variables to simplify builds (?)
    echo "export DIST_OUTPUT_BUCKET=$bucket" > "$deployment_dir"/setenv.sh
    echo "export DIST_VERSION=$version" >> "$deployment_dir"/setenv.sh

    if [[ ! -e "$deployment_dir"/solution_env.sh ]]; then
        echo "solution_env.sh is missing from the solution root." && exit 1
    fi

    source "$deployment_dir"/solution_env.sh

    if [[ -z "$SOLUTION_ID" ]] || [[ -z "$SOLUTION_NAME" ]] || [[ -z "$SOLUTION_TRADEMARKEDNAME" ]]; then
        echo "Missing one of SOLUTION_ID, SOLUTION_NAME, or SOLUTION_TRADEMARKEDNAME from solution_env.sh" && exit 1
    fi

    if [[ ! -z $devtest ]]; then
        SOLUTION_ID=DEV-$SOLUTION_ID
    fi
    export SOLUTION_ID
    export SOLUTION_NAME
    export SOLUTION_TRADEMARKEDNAME

    # You must set BUILD_ENV=development if you wish to run the frontend locally
        if [[ "${BUILD_ENV:-}" != "development" ]]; then
            echo -e "\033[1;33m===============================================================================\033[0m"
            echo -e "\033[1;33m⚠️  WARNING: BUILD_ENV is not set to 'development'. Localhost URLs will not be included in Cognito UserPoolClient configuration.\033[0m"
            echo -e "\033[1;33mTo include localhost URLs for development, run: export BUILD_ENV=development\033[0m"
            echo -e "\033[1;33mThen run: $0 $*\033[0m"
            echo -e "\033[1;33m===============================================================================\033[0m"
            echo ""
            sleep 2
        fi

    echo "export DIST_SOLUTION_NAME=$SOLUTION_TRADEMARKEDNAME" >> ./setenv.sh

    source "$deployment_dir"/setenv.sh

    header "Building $SOLUTION_NAME ($SOLUTION_ID) version $version for bucket $bucket"

    header "[Init] Create folders"
    mkdir -p "$template_dist_dir"
    mkdir -p "$build_dist_dir"
    mkdir -p "$temp_work_dir"
    mkdir -p "$build_dist_dir"/lambda
    mkdir -p "$build_dist_dir"/lambda/blueprints
    mkdir -p "$build_dist_dir"/lambda/blueprints/python
    mkdir -p "$template_dist_dir"/playbooks
    mkdir -p "$template_dist_dir"/blueprints

    header "[Pack] Lambda Layer (used by playbooks)"
    # Check if poetry is available in the shell
      if command -v poetry >/dev/null 2>&1; then
        POETRY_COMMAND="poetry"
      elif [ -n "$POETRY_HOME" ] && [ -x "$POETRY_HOME/bin/poetry" ]; then
        POETRY_COMMAND="$POETRY_HOME/bin/poetry"
      else
        echo "Poetry is not available. Aborting script." >&2
        exit 1
      fi

    "$POETRY_COMMAND" export --without dev -f requirements.txt --output requirements.txt --without-hashes
    pushd "$temp_work_dir"
    mkdir -p "$temp_work_dir"/source/solution_deploy/lambdalayer/python/layer
    mkdir -p "$temp_work_dir"/source/solution_deploy/lambdalayer/python/lib/python3.11/site-packages
    cp "$source_dir"/layer/*.py "$temp_work_dir"/source/solution_deploy/lambdalayer/python/layer
    pip install -r "$deployment_dir"/requirements.txt -t "$temp_work_dir"/source/solution_deploy/lambdalayer/python/lib/python3.11/site-packages
    popd

    pushd "$temp_work_dir"/source/solution_deploy/lambdalayer
    zip --recurse-paths "$build_dist_dir"/lambda/layer.zip python
    popd

    header "[Pack] Custom Action Lambda"

    pushd "$source_dir"/solution_deploy/source
    zip -q ${build_dist_dir}/lambda/action_target_provider.zip action_target_provider.py cfnresponse.py
    popd

    header "[Pack] Deployment Metrics Custom Action Lambda"

    pushd "$source_dir"/solution_deploy/source
    zip -q ${build_dist_dir}/lambda/deployment_metrics_custom_resource.zip deployment_metrics_custom_resource.py cfnresponse.py
    popd

    header "[Pack] Remediation Configuration Custom Action Lambda"

    pushd "$source_dir"/solution_deploy/source
    zip -q ${build_dist_dir}/lambda/remediation_config_provider.zip remediation_config_provider.py cfnresponse.py
    popd

    header "[Pack] Enable Adaptive Concurrency Custom Action Lambda"

    pushd "$source_dir"/solution_deploy/source
    zip -q ${build_dist_dir}/lambda/enable_adaptive_concurrency.zip enable_adaptive_concurrency.py cfnresponse.py
    popd

    header "[Pack] Wait Provider Lambda"

    pushd "$source_dir"/solution_deploy/source
    zip -q ${build_dist_dir}/lambda/wait_provider.zip wait_provider.py cfnresponse.py
    popd

    header "[Pack] Orchestrator Lambdas"

    pushd "$source_dir"/Orchestrator
    ls | while read file; do
        if [ ! -d $file ]; then
            zip -q "$build_dist_dir"/lambda/"${file%.*}".zip "$file"
        fi
    done
    popd

    header "[Build] Data-models"
    pushd "$source_dir"/data-models
    npm run clean && npm install && npm run build
    popd

    header "[Pack] Non-Orchestrator Lambdas"
    pushd "$source_dir"/lambdas
    npm run build:clean && npm run build:install && npm run build:ts
    zip -r -q "$build_dist_dir"/lambda/asr_lambdas.zip . -x "__tests__/*" "*.ts" "**/*.ts" "**/jest.config.js"
    popd

    header "[Pack] Blueprint Lambdas"

    pushd "$source_dir"/blueprints
    "$POETRY_COMMAND" export -f requirements.txt --output requirements.txt --without-hashes
    for dir in */; do
        if [ $dir == 'cdk/' ]; then
          continue
        fi

        pushd $dir/ticket_generator
        ls | while read file; do
            if [ ! -d $file ]; then
                zip -q "$build_dist_dir"/lambda/blueprints/"${file%.*}".zip "$file"
            fi
        done
        popd
    done
    popd

    # Blueprint lambdas dependency layer
    pushd "$build_dist_dir"/lambda/blueprints
    mkdir -p "$build_dist_dir"/lambda/blueprints/python
    "$POETRY_COMMAND" export --without dev -f requirements.txt --output requirements.txt --without-hashes
    pip install -r "$source_dir"/blueprints/requirements.txt -t "$build_dist_dir"/lambda/blueprints/python
    zip -qr python.zip python/*
    rm -r python
    popd


    header "Run UI Builds"

    cd "$source_dir/webui/" || exit 1
    npm install
    GENERATE_SOURCEMAP=false INLINE_RUNTIME_CHUNK=false npm run build

    if [ $? -eq 0 ]
    then
    header "UI build succeeded"
    else
    header "UI build FAILED"
    exit 1
    fi
    mkdir -p "$build_dist_dir"/webui/
    cp -r ./dist/* "$build_dist_dir"/webui/


    header "Generate webui manifest file (webui-manifest.json)"
    # Build webui-manifest.json so that it can be deployed with the ui code afterwards
    #
    # Details: The deployWebui custom resource needs this list in order to copy
    # files from $build_dist_dir/webui to the CloudFront S3 bucket.
    # Since the manifest file is computed during build time, the custom resource
    # can use that to figure out what files to copy instead of doing a list bucket operation,
    # which would require ListBucket permission.
    # Furthermore, the S3 bucket used to host AWS solutions disallows ListBucket
    # access, so the only way to copy the webui files from that bucket from
    # to CloudFront S3 bucket is to use a manifest file.

    cd $deployment_dir/manifest-generator
    [ -e node_modules ] && rm -rf node_modules
    npm ci
    node app.js --target "$build_dist_dir/webui" --output webui-manifest.json
    mv webui-manifest.json $build_dist_dir/webui/webui-manifest.json

    # IMPORTANT: Pack all lambda assets before this line

    header "[Generate] Lambda Content Hashes"

    # Generate content hashes for all Lambda zip files recursively
    temp_mappings="$temp_work_dir/lambda_mappings.txt"
    > "$temp_mappings"

    find "$build_dist_dir"/lambda -type f -name "*.zip" | while read -r zip_file; do
        relative_path="${zip_file#$build_dist_dir/lambda/}"
        dir_path=$(dirname "$relative_path")
        filename=$(basename "$zip_file")
        hash=$(sha256sum "$zip_file" | cut -d' ' -f1 | cut -c1-8)
        hashed_filename="${filename%.zip}-${hash}.zip"
        
        if [ "$dir_path" = "." ]; then
            mv "$zip_file" "$build_dist_dir"/lambda/"$hashed_filename"
            echo "$filename|$hashed_filename" >> "$temp_mappings"
            echo "Generated hash for $filename: $hash"
        else
            mv "$zip_file" "$build_dist_dir"/lambda/"$dir_path"/"$hashed_filename"
            echo "$dir_path/$filename|$dir_path/$hashed_filename" >> "$temp_mappings"
            echo "Generated hash for $dir_path/$filename: $hash"
        fi
    done

    # Create hash manifest file for CDK to read
    echo "{" > "$build_dist_dir"/lambda/lambda-hashes.json

    # Add each hash mapping to the JSON file
    first=true
    while IFS='|' read -r original hashed; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$build_dist_dir"/lambda/lambda-hashes.json
        fi
        echo -n "  \"$original\": \"$hashed\"" >> "$build_dist_dir"/lambda/lambda-hashes.json
    done < "$temp_mappings"

    echo "" >> "$build_dist_dir"/lambda/lambda-hashes.json
    echo "}" >> "$build_dist_dir"/lambda/lambda-hashes.json

    header "[Create] Playbooks"

    for playbook in $(ls "$source_dir"/playbooks); do
        if [ $playbook == 'NEWPLAYBOOK' ] || [ $playbook == '.coverage' ] || [ $playbook == 'common' ] || [ $playbook == 'playbook-index.ts' ] || [ $playbook == 'split_member_stacks.ts' ]; then
            continue
        fi
        echo Create $playbook playbook
        pushd "$source_dir"/playbooks/"$playbook"
        npx cdk synth --asset-metadata false --path-metadata false --version-reporting false --quiet
        cd cdk.out
        for template in $(ls *.template.json); do
            cp "$template" "$template_dist_dir"/playbooks/${template%.json}
        done
        popd
    done

   header "[Create] Blueprint templates"

   pushd "$source_dir"/blueprints
       for blueprintDir in */; do
           if [ $blueprintDir == 'cdk/' ]; then
            continue
           fi

           pushd ${blueprintDir}/cdk
           echo Create $blueprintDir blueprint
           npx cdk synth --asset-metadata false --path-metadata false --version-reporting false --quiet
           cd cdk.out
           for template in $(ls *.template.json); do
               cp "$template" "$template_dist_dir"/blueprints/${template%.json}
           done
           popd
       done
   popd

  header "[Create] Deployment Templates"

  pushd "$source_dir"/solution_deploy

  npx cdk synth --asset-metadata false --path-metadata false --version-reporting false --quiet
  cd cdk.out
  for template in $(ls *.template.json); do
      cp "$template" "$template_dist_dir"/${template%.json}
  done
  popd

  [ -e "$deployment_dir"/*.template ] && cp "$deployment_dir"/*.template "$template_dist_dir"/

  mv "$template_dist_dir"/SolutionDeployStack.template "$template_dist_dir"/automated-security-response-admin.template
  mv "$template_dist_dir"/MemberStack.template "$template_dist_dir"/automated-security-response-member.template
  mv "$template_dist_dir"/MemberCloudTrail*.template "$template_dist_dir"/automated-security-response-member-cloudtrail.template
  mv "$template_dist_dir"/RunbookStack.template "$template_dist_dir"/automated-security-response-remediation-runbooks.template
  mv "$template_dist_dir"/OrchestratorLogStack.template "$template_dist_dir"/automated-security-response-orchestrator-log.template
  mv "$template_dist_dir"/MemberRolesStack.template "$template_dist_dir"/automated-security-response-member-roles.template
  mv "$template_dist_dir"/SolutionDeployStackWebUINestedStack*.template "$template_dist_dir"/automated-security-response-webui-nested-stack.template
  rm "$template_dist_dir"/*.nested.template

  header "[Create] List of Supported Control Ids (supported-controls.json)"
  node "$deployment_dir"/utils/generate-controls-list.js "$version"
}

main "$@"
