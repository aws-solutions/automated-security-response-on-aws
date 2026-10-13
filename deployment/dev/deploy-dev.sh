#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# One-command BUILD and DEPLOY for ASR dev environments.
# Reads configuration from local-config.json (created by init.sh).
#
# Usage:
#   ./deploy-dev.sh              # Auto-detects: update if stacks exist, create otherwise
#   ./deploy-dev.sh create       # (or "c") Build, upload, and create all stacks
#   ./deploy-dev.sh update       # (or "u") Build, upload, and update all stacks in place
#   ./deploy-dev.sh delete       # (or "d") Delete all stacks

set -eu -o pipefail

export BUILD_ENV=development
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOYMENT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/local-config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "local-config.json not found. Run init.sh first."
    exit 1
fi

# --- Read/write config ---

read_config() {
    node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))[process.argv[2]])" "$CONFIG_FILE" "$1"
}

read_config_optional() {
    node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))[process.argv[2]]||'')" "$CONFIG_FILE" "$1" 2>/dev/null || echo ""
}

# Prints "yes" if the key is present in local-config.json, "no" otherwise. Distinct
# from read_config_optional, which cannot tell an absent key from an empty value.
config_has_key() {
    node -e "process.stdout.write(Object.prototype.hasOwnProperty.call(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8')),process.argv[2])?'yes':'no')" "$CONFIG_FILE" "$1" 2>/dev/null || echo "no"
}

write_config() {
    node -e "
const fs=require('fs'),p=process.argv[1],k=process.argv[2],v=process.argv[3];
const c=JSON.parse(fs.readFileSync(p,'utf8'));c[k]=v;
fs.writeFileSync(p,JSON.stringify(c,null,2)+'\n')
" "$CONFIG_FILE" "$1" "$2"
}

ACCOUNT_ID=$(read_config accountId)
REGION=$(read_config region)
NAMESPACE=$(read_config namespace)
BASE_BUCKET_NAME=$(read_config baseBucketName)
TEMPLATE_BUCKET_NAME=$(read_config templateBucketName)
ASSET_BUCKET_NAME=$(read_config assetBucketName)
SOLUTION_NAME=$(read_config solutionName)
SOLUTION_VERSION=$(read_config solutionVersion)
SECHUB_ADMIN_ACCOUNT=$(read_config secHubAdminAccount)
ADMIN_USER_EMAIL=$(read_config_optional adminUserEmail)
ENABLE_MCP_SERVER=$(read_config_optional enableMcpServer)
ENABLE_MCP_SERVER=${ENABLE_MCP_SERVER:-no}
ADDITIONAL_MCP_CALLBACK_URLS=$(read_config_optional additionalMcpCallbackUrls)

if [ "$ENABLE_MCP_SERVER" != "yes" ] && [ "$ENABLE_MCP_SERVER" != "no" ]; then
    echo "ERROR: enableMcpServer in local-config.json must be 'yes' or 'no'."
    exit 1
fi

if [[ "$ADDITIONAL_MCP_CALLBACK_URLS" =~ [[:space:]] ]]; then
    echo "ERROR: additionalMcpCallbackUrls in local-config.json must not contain whitespace."
    exit 1
fi

# AWS CLI shorthand treats unescaped commas as structure delimiters. Preserve the
# CommaDelimitedList value as one ParameterValue string.
ESCAPED_ADDITIONAL_MCP_CALLBACK_URLS=${ADDITIONAL_MCP_CALLBACK_URLS//,/\\,}

# On update, only pass explicit MCP values when the config actually carries the key;
# otherwise keep the deployed value. This stops an unrelated update from silently
# flipping EnableMcpServer back to its "no" default and tearing down the gateway.
if [ "$(config_has_key enableMcpServer)" = "yes" ]; then
    ENABLE_MCP_SERVER_UPDATE_PARAM="ParameterKey=EnableMcpServer,ParameterValue=$ENABLE_MCP_SERVER"
else
    ENABLE_MCP_SERVER_UPDATE_PARAM="ParameterKey=EnableMcpServer,UsePreviousValue=true"
fi
if [ "$(config_has_key additionalMcpCallbackUrls)" = "yes" ]; then
    ADDITIONAL_MCP_CALLBACK_URLS_UPDATE_PARAM="ParameterKey=AdditionalMcpCallbackUrls,ParameterValue=$ESCAPED_ADDITIONAL_MCP_CALLBACK_URLS"
else
    ADDITIONAL_MCP_CALLBACK_URLS_UPDATE_PARAM="ParameterKey=AdditionalMcpCallbackUrls,UsePreviousValue=true"
fi

ADMIN_STACK="ASR-Admin-$NAMESPACE"
MEMBER_STACK="ASR-Member-$NAMESPACE"
MEMBER_ROLES_STACK="ASR-Member-Roles-$NAMESPACE"

# --- Resolve action ---

ACTION="${1:-}"
if [ -z "$ACTION" ]; then
    if [ -n "$(read_config_optional adminStackId)" ]; then
        ACTION=update
        echo "(Stack IDs found in config — defaulting to update)"
    else
        ACTION=create
        echo "(No stack IDs in config — defaulting to create)"
    fi
fi

echo "=== ASR Dev Deploy ($ACTION) ==="
echo "Account:   $ACCOUNT_ID"
echo "Region:    $REGION"
echo "Namespace: $NAMESPACE"
echo "Version:   $SOLUTION_VERSION"
echo "MCP Server: $ENABLE_MCP_SERVER"
echo ""

# --- Verify AWS credentials ---

echo "Verifying AWS credentials..."
if ! aws sts get-caller-identity --region "$REGION" > /dev/null 2>&1; then
    echo "ERROR: No valid AWS credentials found."
    echo "Configure credentials via 'aws configure', environment variables, or an IAM role."
    exit 1
fi
echo "AWS credentials valid. ✓"
echo ""

# --- Build and upload (shared by create and update) ---

build_and_upload() {
    echo "Building solution..."
    cd "$DEPLOYMENT_DIR"
    ./build-s3-dist.sh -b "$BASE_BUCKET_NAME" -v "$SOLUTION_VERSION"

    echo "Uploading artifacts..."
    ./upload-s3-dist.sh -y "$REGION"
}

# --- Shared definitions ---

# --- Detect existing orchestrator log group ---

if aws logs describe-log-groups --log-group-name-prefix "SO0111-ASR-Orchestrator" --region "$REGION" \
    --query 'logGroups[?logGroupName==`SO0111-ASR-Orchestrator`]' --output text 2>/dev/null | grep -q .; then
    REUSE_LOG_GROUP=yes
    echo "Orchestrator log group already exists — setting ReuseOrchestratorLogGroup=yes"
else
    REUSE_LOG_GROUP=no
fi

ADMIN_TEMPLATE_URL="https://$TEMPLATE_BUCKET_NAME.s3.$REGION.amazonaws.com/$SOLUTION_NAME/$SOLUTION_VERSION/automated-security-response-admin.template"
MEMBER_TEMPLATE_URL="https://$TEMPLATE_BUCKET_NAME.s3.$REGION.amazonaws.com/$SOLUTION_NAME/$SOLUTION_VERSION/automated-security-response-member.template"
MEMBER_ROLES_TEMPLATE_URL="https://$TEMPLATE_BUCKET_NAME.s3.$REGION.amazonaws.com/$SOLUTION_NAME/$SOLUTION_VERSION/automated-security-response-member-roles.template"

ADMIN_PARAMS="\
    ParameterKey=LoadSCAdminStack,ParameterValue=yes \
    ParameterKey=LoadAFSBPAdminStack,ParameterValue=no \
    ParameterKey=LoadCIS120AdminStack,ParameterValue=no \
    ParameterKey=LoadCIS140AdminStack,ParameterValue=no \
    ParameterKey=LoadCIS300AdminStack,ParameterValue=no \
    ParameterKey=LoadNIST80053AdminStack,ParameterValue=no \
    ParameterKey=LoadPCI321AdminStack,ParameterValue=no \
    ParameterKey=ReuseOrchestratorLogGroup,ParameterValue=$REUSE_LOG_GROUP \
    ParameterKey=UseCloudWatchMetrics,ParameterValue=yes \
    ParameterKey=UseCloudWatchMetricsAlarms,ParameterValue=yes \
    ParameterKey=RemediationFailureAlarmThreshold,ParameterValue=5 \
    ParameterKey=EnableEnhancedCloudWatchMetrics,ParameterValue=no \
    ParameterKey=Namespace,ParameterValue=$NAMESPACE \
    ParameterKey=ShouldDeployWebUI,ParameterValue=yes \
    ParameterKey=EnableMcpServer,ParameterValue=$ENABLE_MCP_SERVER \
    ParameterKey=AdditionalMcpCallbackUrls,ParameterValue=$ESCAPED_ADDITIONAL_MCP_CALLBACK_URLS \
    ParameterKey=AdminUserEmail,ParameterValue=$ADMIN_USER_EMAIL \
    ParameterKey=TicketGenFunctionName,ParameterValue="

ADMIN_PARAMS="$ADMIN_PARAMS \
    ParameterKey=EnableRollback,ParameterValue=yes"

MEMBER_PARAMS="\
    ParameterKey=LoadSCMemberStack,ParameterValue=yes \
    ParameterKey=LoadAFSBPMemberStack,ParameterValue=no \
    ParameterKey=LoadCIS120MemberStack,ParameterValue=no \
    ParameterKey=LoadCIS140MemberStack,ParameterValue=no \
    ParameterKey=LoadCIS300MemberStack,ParameterValue=no \
    ParameterKey=LoadNIST80053MemberStack,ParameterValue=no \
    ParameterKey=LoadPCI321MemberStack,ParameterValue=no \
    ParameterKey=CreateS3BucketForRedshiftAuditLogging,ParameterValue=no \
    ParameterKey=LogGroupName,ParameterValue=asr-log-group-$NAMESPACE \
    ParameterKey=Namespace,ParameterValue=$NAMESPACE \
    ParameterKey=SecHubAdminAccount,ParameterValue=$SECHUB_ADMIN_ACCOUNT \
    ParameterKey=EnableCloudTrailForASRActionLog,ParameterValue=no"

MEMBER_ROLES_PARAMS="\
    ParameterKey=Namespace,ParameterValue=$NAMESPACE \
    ParameterKey=SecHubAdminAccount,ParameterValue=$SECHUB_ADMIN_ACCOUNT"

# --- UsePreviousValue params for updates (keep existing stack parameters) ---

ADMIN_UPDATE_PARAMS="\
    ParameterKey=LoadSCAdminStack,UsePreviousValue=true \
    ParameterKey=LoadAFSBPAdminStack,UsePreviousValue=true \
    ParameterKey=LoadCIS120AdminStack,UsePreviousValue=true \
    ParameterKey=LoadCIS140AdminStack,UsePreviousValue=true \
    ParameterKey=LoadCIS300AdminStack,UsePreviousValue=true \
    ParameterKey=LoadNIST80053AdminStack,UsePreviousValue=true \
    ParameterKey=LoadPCI321AdminStack,UsePreviousValue=true \
    ParameterKey=ReuseOrchestratorLogGroup,UsePreviousValue=true \
    ParameterKey=UseCloudWatchMetrics,UsePreviousValue=true \
    ParameterKey=UseCloudWatchMetricsAlarms,UsePreviousValue=true \
    ParameterKey=RemediationFailureAlarmThreshold,UsePreviousValue=true \
    ParameterKey=EnableEnhancedCloudWatchMetrics,UsePreviousValue=true \
    ParameterKey=Namespace,UsePreviousValue=true \
    ParameterKey=ShouldDeployWebUI,UsePreviousValue=true \
    $ENABLE_MCP_SERVER_UPDATE_PARAM \
    $ADDITIONAL_MCP_CALLBACK_URLS_UPDATE_PARAM \
    ParameterKey=AdminUserEmail,UsePreviousValue=true \
    ParameterKey=TicketGenFunctionName,UsePreviousValue=true \
    ParameterKey=EnableRollback,ParameterValue=yes"

MEMBER_UPDATE_PARAMS="\
    ParameterKey=LoadSCMemberStack,UsePreviousValue=true \
    ParameterKey=LoadAFSBPMemberStack,UsePreviousValue=true \
    ParameterKey=LoadCIS120MemberStack,UsePreviousValue=true \
    ParameterKey=LoadCIS140MemberStack,UsePreviousValue=true \
    ParameterKey=LoadCIS300MemberStack,UsePreviousValue=true \
    ParameterKey=LoadNIST80053MemberStack,UsePreviousValue=true \
    ParameterKey=LoadPCI321MemberStack,UsePreviousValue=true \
    ParameterKey=CreateS3BucketForRedshiftAuditLogging,UsePreviousValue=true \
    ParameterKey=LogGroupName,UsePreviousValue=true \
    ParameterKey=Namespace,UsePreviousValue=true \
    ParameterKey=SecHubAdminAccount,UsePreviousValue=true \
    ParameterKey=EnableCloudTrailForASRActionLog,UsePreviousValue=true"

MEMBER_ROLES_UPDATE_PARAMS="\
    ParameterKey=Namespace,UsePreviousValue=true \
    ParameterKey=SecHubAdminAccount,UsePreviousValue=true"

# --- Deploy a single stack (create or update) ---
# Usage: deploy_stack <create|update> <stack-name> <template-url> <params...>
# Returns the stack ID via LAST_STACK_ID, or "SKIPPED" if no updates needed.

LAST_STACK_ID=""

deploy_stack() {
    local verb="$1" stack_name="$2" template_url="$3"
    shift 3

    echo "$(echo "$verb" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')ing $stack_name..."

    local extra_flags=""
    local wait_event="stack-${verb}-complete"
    if [ "$verb" = "create" ]; then
        extra_flags="--disable-rollback"
    fi

    local output
    # Word splitting on $@ is intentional — params are space-separated strings
    if output=$(aws cloudformation "${verb}-stack" \
            --capabilities CAPABILITY_NAMED_IAM $extra_flags \
            --stack-name "$stack_name" --template-url "$template_url" \
            --region "$REGION" \
            --parameters $@ \
            --output text --query 'StackId' 2>&1); then
        LAST_STACK_ID="$output"
        echo "Waiting for $stack_name..."
        aws cloudformation wait "$wait_event" --stack-name "$stack_name" --region "$REGION"
    elif [[ "$output" == *"No updates are to be performed"* ]]; then
        LAST_STACK_ID="SKIPPED"
        echo "No updates for $stack_name, skipping."
    else
        echo "$output" >&2
        exit 1
    fi
}

case "$ACTION" in
    c|create)
        build_and_upload

        deploy_stack create "$ADMIN_STACK" "$ADMIN_TEMPLATE_URL" $ADMIN_PARAMS
        ADMIN_ID="$LAST_STACK_ID"

        deploy_stack create "$MEMBER_ROLES_STACK" "$MEMBER_ROLES_TEMPLATE_URL" $MEMBER_ROLES_PARAMS
        MEMBER_ROLES_ID="$LAST_STACK_ID"

        deploy_stack create "$MEMBER_STACK" "$MEMBER_TEMPLATE_URL" $MEMBER_PARAMS
        MEMBER_ID="$LAST_STACK_ID"

        write_config adminStackId "$ADMIN_ID"
        write_config memberStackId "$MEMBER_ID"
        write_config memberRolesStackId "$MEMBER_ROLES_ID"

        echo ""
        echo "=== All stacks created successfully ==="
        echo "Admin:        $ADMIN_ID"
        echo "Member:       $MEMBER_ID"
        echo "Member Roles: $MEMBER_ROLES_ID"
        ;;

    u|update)
        build_and_upload

        # Use stored stack IDs (ARNs) when available, fall back to constructed names
        ADMIN_STACK_REF=$(read_config_optional adminStackId)
        ADMIN_STACK_REF=${ADMIN_STACK_REF:-$ADMIN_STACK}
        MEMBER_STACK_REF=$(read_config_optional memberStackId)
        MEMBER_STACK_REF=${MEMBER_STACK_REF:-$MEMBER_STACK}
        MEMBER_ROLES_STACK_REF=$(read_config_optional memberRolesStackId)
        MEMBER_ROLES_STACK_REF=${MEMBER_ROLES_STACK_REF:-$MEMBER_ROLES_STACK}

        deploy_stack update "$ADMIN_STACK_REF" "$ADMIN_TEMPLATE_URL" $ADMIN_UPDATE_PARAMS
        ADMIN_ID="$LAST_STACK_ID"

        deploy_stack update "$MEMBER_ROLES_STACK_REF" "$MEMBER_ROLES_TEMPLATE_URL" $MEMBER_ROLES_UPDATE_PARAMS
        MEMBER_ROLES_ID="$LAST_STACK_ID"

        deploy_stack update "$MEMBER_STACK_REF" "$MEMBER_TEMPLATE_URL" $MEMBER_UPDATE_PARAMS
        MEMBER_ID="$LAST_STACK_ID"

        # Only save IDs for stacks that were actually updated
        if [ "$ADMIN_ID" != "SKIPPED" ]; then write_config adminStackId "$ADMIN_ID"; fi
        if [ "$MEMBER_ID" != "SKIPPED" ]; then write_config memberStackId "$MEMBER_ID"; fi
        if [ "$MEMBER_ROLES_ID" != "SKIPPED" ]; then write_config memberRolesStackId "$MEMBER_ROLES_ID"; fi

        echo ""
        echo "=== Update complete ==="
        echo "Admin:        $ADMIN_ID"
        echo "Member:       $MEMBER_ID"
        echo "Member Roles: $MEMBER_ROLES_ID"
        ;;

    d|delete)
        # ASR declares its stateful resources (S3 buckets, DynamoDB tables, the
        # SO0111-* IAM roles/instance profiles, the remediation-config-bucket
        # managed policy) with RemovalPolicy.RETAIN so that in production a stack
        # teardown never destroys data or breaks in-flight
        # remediations. In a dev account we always recreate from scratch, so those
        # orphans just collide with the next deploy on their fixed names. This
        # branch discovers the retained resources from the stack trees, deletes the
        # stacks, then tears the orphans down for a clean recreate. Log groups are
        # left in place, matching the Implementation Guide's recommendation.

        # Physical IDs gathered before deletion (RETAIN resources outlive the stack).
        ORPHAN_BUCKETS=()
        ORPHAN_TABLES=()
        ORPHAN_PROFILES=()
        ORPHAN_ROLES=()
        ORPHAN_POLICIES=()

        # Recursively collect resource physical IDs by type from a stack and its
        # nested stacks. Gathers every candidate; survivors are filtered after the
        # stacks are deleted, so the removal policy never has to be inferred here.
        collect_retained_resources() {
            local stack="$1"
            aws cloudformation describe-stacks --stack-name "$stack" --region "$REGION" >/dev/null 2>&1 || return 0

            local resources
            resources=$(aws cloudformation list-stack-resources --stack-name "$stack" --region "$REGION" \
                --query 'StackResourceSummaries[].[ResourceType,PhysicalResourceId]' --output text 2>/dev/null) || return 0

            while IFS=$'\t' read -r rtype pid; do
                [ -z "$rtype" ] && continue
                [ -z "$pid" ] && continue
                case "$rtype" in
                    AWS::S3::Bucket)           ORPHAN_BUCKETS+=("$pid") ;;
                    AWS::DynamoDB::Table)      ORPHAN_TABLES+=("$pid") ;;
                    AWS::IAM::InstanceProfile) ORPHAN_PROFILES+=("$pid") ;;
                    AWS::IAM::Role)            ORPHAN_ROLES+=("$pid") ;;
                    # PhysicalResourceId is the policy ARN. Retained managed
                    # policies carry fixed names, so a leftover one fails the next
                    # create in EarlyValidation::ResourceExistenceCheck rather than
                    # on the resource itself — an error that names no resource.
                    AWS::IAM::ManagedPolicy)   ORPHAN_POLICIES+=("$pid") ;;
                    AWS::CloudFormation::Stack) collect_retained_resources "$pid" ;;
                esac
            done <<< "$resources"
        }

        # --- Orphan teardown helpers (no-op if the resource was not retained) ---

        delete_orphan_bucket() {
            local bucket="$1"
            aws s3api head-bucket --bucket "$bucket" --region "$REGION" >/dev/null 2>&1 || return 0
            echo "  Emptying and deleting bucket $bucket..."
            # Buckets are versioned, so every version and delete marker must go
            # before the bucket can be removed. Loop to handle >1000 objects.
            while true; do
                local payload
                payload=$(aws s3api list-object-versions --bucket "$bucket" --region "$REGION" --max-items 500 \
                    --query '{Objects: [Versions, DeleteMarkers][].{Key:Key,VersionId:VersionId}}' \
                    --output json 2>/dev/null) || break
                case "$payload" in
                    ''|*'"Objects": []'*|*'"Objects": null'*) break ;;
                esac
                aws s3api delete-objects --bucket "$bucket" --region "$REGION" --delete "$payload" >/dev/null 2>&1 || break
            done
            aws s3api delete-bucket --bucket "$bucket" --region "$REGION" >/dev/null 2>&1 \
                && echo "    bucket $bucket deleted." || echo "    Warning: could not delete bucket $bucket"
        }

        delete_orphan_table() {
            local table="$1"
            aws dynamodb describe-table --table-name "$table" --region "$REGION" >/dev/null 2>&1 || return 0
            echo "  Deleting table $table..."
            # Tables carry deletionProtection=true; clear it before deleting.
            aws dynamodb update-table --table-name "$table" --region "$REGION" \
                --no-deletion-protection-enabled >/dev/null 2>&1 || true
            aws dynamodb delete-table --table-name "$table" --region "$REGION" >/dev/null 2>&1 \
                && echo "    table $table deleted." || echo "    Warning: could not delete table $table"
        }

        delete_orphan_instance_profile() {
            local profile="$1"
            aws iam get-instance-profile --instance-profile-name "$profile" >/dev/null 2>&1 || return 0
            echo "  Deleting instance profile $profile..."
            # A role cannot be deleted while still attached to a profile.
            local attached_roles
            attached_roles=$(aws iam get-instance-profile --instance-profile-name "$profile" \
                --query 'InstanceProfile.Roles[].RoleName' --output text 2>/dev/null) || attached_roles=""
            for role in $attached_roles; do
                aws iam remove-role-from-instance-profile \
                    --instance-profile-name "$profile" --role-name "$role" >/dev/null 2>&1 || true
            done
            aws iam delete-instance-profile --instance-profile-name "$profile" >/dev/null 2>&1 \
                && echo "    instance profile $profile deleted." || echo "    Warning: could not delete instance profile $profile"
        }

        delete_orphan_role() {
            local role="$1"
            aws iam get-role --role-name "$role" >/dev/null 2>&1 || return 0
            echo "  Deleting role $role..."
            local arn pol profile
            for arn in $(aws iam list-attached-role-policies --role-name "$role" \
                    --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null); do
                aws iam detach-role-policy --role-name "$role" --policy-arn "$arn" >/dev/null 2>&1 || true
            done
            for pol in $(aws iam list-role-policies --role-name "$role" \
                    --query 'PolicyNames[]' --output text 2>/dev/null); do
                aws iam delete-role-policy --role-name "$role" --policy-name "$pol" >/dev/null 2>&1 || true
            done
            for profile in $(aws iam list-instance-profiles-for-role --role-name "$role" \
                    --query 'InstanceProfiles[].InstanceProfileName' --output text 2>/dev/null); do
                aws iam remove-role-from-instance-profile \
                    --instance-profile-name "$profile" --role-name "$role" >/dev/null 2>&1 || true
            done
            aws iam delete-role --role-name "$role" >/dev/null 2>&1 \
                && echo "    role $role deleted." || echo "    Warning: could not delete role $role"
        }

        delete_orphan_managed_policy() {
            local policy_arn="$1"
            [ -n "$policy_arn" ] || return 0
            aws iam get-policy --policy-arn "$policy_arn" >/dev/null 2>&1 || return 0
            echo "  Deleting managed policy $policy_arn..."
            # A policy cannot be deleted while attached to anything, nor while it
            # has non-default versions. Each detach target is named as it is
            # processed: ASR attaches the remediation-config-bucket policy to IAM
            # identities it did not create (the Inspector remediation attaches it to
            # whatever role the target instance already had), so the operator needs a
            # record of which identities this teardown modified.
            local entity
            for entity in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" \
                    --query 'PolicyRoles[].RoleName' --output text 2>/dev/null); do
                echo "    detaching from role $entity"
                aws iam detach-role-policy --role-name "$entity" --policy-arn "$policy_arn" >/dev/null 2>&1 \
                    || echo "    Warning: could not detach from role $entity"
            done
            for entity in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" \
                    --query 'PolicyGroups[].GroupName' --output text 2>/dev/null); do
                echo "    detaching from group $entity"
                aws iam detach-group-policy --group-name "$entity" --policy-arn "$policy_arn" >/dev/null 2>&1 \
                    || echo "    Warning: could not detach from group $entity"
            done
            for entity in $(aws iam list-entities-for-policy --policy-arn "$policy_arn" \
                    --query 'PolicyUsers[].UserName' --output text 2>/dev/null); do
                echo "    detaching from user $entity"
                aws iam detach-user-policy --user-name "$entity" --policy-arn "$policy_arn" >/dev/null 2>&1 \
                    || echo "    Warning: could not detach from user $entity"
            done
            local version
            for version in $(aws iam list-policy-versions --policy-arn "$policy_arn" \
                    --query 'Versions[?!IsDefaultVersion].VersionId' --output text 2>/dev/null); do
                aws iam delete-policy-version --policy-arn "$policy_arn" --version-id "$version" >/dev/null 2>&1 || true
            done
            aws iam delete-policy --policy-arn "$policy_arn" >/dev/null 2>&1 \
                && echo "    managed policy $policy_arn deleted." || echo "    Warning: could not delete managed policy $policy_arn"
        }

        echo "Teardown deletes the remediation configuration bucket and detaches its"
        echo "access policy from every IAM identity holding it, including EC2 instance"
        echo "roles ASR attached it to. An Inspector remediation running right now will"
        echo "fail. Each detached identity is named below."
        echo ""

        echo "Discovering retained resources before deletion..."
        for stack in "$MEMBER_STACK" "$MEMBER_ROLES_STACK" "$ADMIN_STACK"; do
            collect_retained_resources "$stack"
        done

        echo "Deleting stacks..."
        for stack in "$MEMBER_STACK" "$MEMBER_ROLES_STACK" "$ADMIN_STACK"; do
            echo "Deleting $stack..."
            aws cloudformation delete-stack --stack-name "$stack" --region "$REGION" \
                || { echo "Warning: delete-stack failed for $stack"; continue; }
            aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION" \
                || { echo "Warning: $stack may not have been fully deleted"; continue; }
            echo "$stack deleted."
        done

        # Tear down the resources CloudFormation retained. Order matters: instance
        # profiles must be detached before their roles can be deleted.
        echo "Cleaning up retained resources..."
        for bucket in "${ORPHAN_BUCKETS[@]:-}"; do [ -n "$bucket" ] && delete_orphan_bucket "$bucket"; done
        for table in "${ORPHAN_TABLES[@]:-}"; do [ -n "$table" ] && delete_orphan_table "$table"; done
        for profile in "${ORPHAN_PROFILES[@]:-}"; do [ -n "$profile" ] && delete_orphan_instance_profile "$profile"; done
        for role in "${ORPHAN_ROLES[@]:-}"; do [ -n "$role" ] && delete_orphan_role "$role"; done
        # Policies last: deleting the roles above removes most attachments first,
        # leaving less for the policy's own detach loop to do.
        for policy in "${ORPHAN_POLICIES[@]:-}"; do [ -n "$policy" ] && delete_orphan_managed_policy "$policy"; done

        # Name-based fallback sweep. Stack-tree discovery only sees resources that
        # still have a parent stack, so it cannot reach resources orphaned by an
        # earlier delete (or by a stack removed outside this script). ASR's named,
        # recreation-blocking resources are deterministic from namespace/region/
        # account, so we can clean them by name regardless of stack state.
        # Auto-named buckets (CSV export, access logs) get random suffixes and do
        # not block recreation, so they are intentionally not swept here.
        echo "Fallback sweep for orphaned named resources (namespace $NAMESPACE)..."

        # Namespaced names: a co-located deployment under another namespace owns
        # different names and is never touched by these.
        delete_orphan_bucket "so0111-asr-iac-templates-$NAMESPACE-$REGION-$ACCOUNT_ID"
        delete_orphan_bucket "so0111-asr-$NAMESPACE-management-events-$ACCOUNT_ID"

        # The remediation configuration bucket and the managed policy granting read
        # access to it are the two exceptions: both are named per account+region with
        # NO namespace, so they are shared region-wide rather than scoped to this
        # namespace. Sweeping them is still safe, because those same fixed names make
        # a co-located member deployment impossible — CloudFormation cannot create a
        # second member stack in this account+region while they exist — so whatever is
        # found here belongs to THIS deployment.
        #
        # Deleting the policy detaches it from every identity holding it, which
        # includes EC2 instance roles ASR did not create. Those instances keep their
        # patches and only lose read access to the bucket this teardown deletes
        # anyway; the next deployment's Inspector remediation re-attaches on its next
        # run. An Inspector remediation that is mid-patch right now will fail, so tear
        # down only when no remediation is in flight.
        delete_orphan_bucket "so0111-asr-remediation-$REGION-$ACCOUNT_ID"

        # Resolved by name rather than by a built ARN so the partition is never
        # hardcoded.
        REMEDIATION_POLICY_ARN=$(aws iam list-policies --scope Local \
            --query "Policies[?PolicyName=='ASR-RemediationConfigBucketAccess-$REGION'].Arn | [0]" \
            --output text 2>/dev/null) || REMEDIATION_POLICY_ARN=""
        [ "$REMEDIATION_POLICY_ARN" = "None" ] && REMEDIATION_POLICY_ARN=""
        delete_orphan_managed_policy "$REMEDIATION_POLICY_ARN"

        # SO0111-* IAM roles and instance profiles carry the namespace as a suffix.
        # Listing by that pattern covers every retained remediation role without
        # hardcoding the (growing) list of remediation names. Profiles first.
        for profile in $(aws iam list-instance-profiles \
                --query "InstanceProfiles[?starts_with(InstanceProfileName, 'SO0111-') && ends_with(InstanceProfileName, '-$NAMESPACE')].InstanceProfileName" \
                --output text 2>/dev/null); do
            delete_orphan_instance_profile "$profile"
        done
        for role in $(aws iam list-roles \
                --query "Roles[?starts_with(RoleName, 'SO0111-') && ends_with(RoleName, '-$NAMESPACE')].RoleName" \
                --output text 2>/dev/null); do
            delete_orphan_role "$role"
        done

        # Clear stale stack IDs so next run defaults to create
        node -e "
const fs=require('fs'),p=process.argv[1];
const c=JSON.parse(fs.readFileSync(p,'utf8'));
delete c.adminStackId;delete c.memberStackId;delete c.memberRolesStackId;
fs.writeFileSync(p,JSON.stringify(c,null,2)+'\n')
" "$CONFIG_FILE"

        echo ""
        echo "=== All stacks deleted and retained resources cleaned up ==="
        ;;

    *)
        echo "Usage: $0 [create|c|update|u|delete|d]"
        exit 1
        ;;
esac
