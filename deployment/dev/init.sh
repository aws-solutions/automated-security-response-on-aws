#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Interactive setup for local ASR dev deployments.
# Creates S3 buckets and writes local-config.json for use by deploy-dev.sh.

set -eu -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/local-config.json"

echo "=== ASR Dev Environment Setup ==="
echo ""

if [ -f "$CONFIG_FILE" ]; then
    echo "Existing local-config.json found. Running init again will generate a new"
    echo "namespace and create new buckets (the old ones are NOT deleted)."
    echo ""
    read -p "Continue? (y/n) [n]: " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        exit 0
    fi
    echo ""
fi

# --- Read defaults from existing config (if any) ---

read_existing() {
    node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))[process.argv[2]]||'')" "$CONFIG_FILE" "$1" 2>/dev/null || echo ""
}

if [ -f "$CONFIG_FILE" ]; then
    default_account_id=$(read_existing accountId)
    default_region=$(read_existing region)
    default_sechub=$(read_existing secHubAdminAccount)
    default_version=$(read_existing solutionVersion)
    default_admin_email=$(read_existing adminUserEmail)
fi
default_region=${default_region:-us-east-1}
default_version=${default_version:-v4.0.0.dev}

# --- Collect values ---

if [ -n "${default_account_id:-}" ]; then
    read -p "AWS Account ID [$default_account_id]: " account_id
    account_id=${account_id:-$default_account_id}
else
    read -p "AWS Account ID: " account_id
fi
if [ -z "$account_id" ]; then
    echo "Account ID is required."
    exit 1
fi

read -p "AWS Region [$default_region]: " region
region=${region:-$default_region}

default_sechub=${default_sechub:-$account_id}
read -p "Security Hub Admin Account ID [$default_sechub]: " sechub_admin_account
sechub_admin_account=${sechub_admin_account:-$default_sechub}

read -p "Solution version [$default_version]: " solution_version
solution_version=${solution_version:-$default_version}

if [ -n "${default_admin_email:-}" ]; then
    read -p "WebUI admin user email [$default_admin_email]: " admin_user_email
    admin_user_email=${admin_user_email:-$default_admin_email}
else
    read -p "WebUI admin user email: " admin_user_email
fi
if [ -z "$admin_user_email" ]; then
    echo "WebUI admin user email is required (Cognito sends the initial login here)."
    exit 1
fi

# --- Generate namespace and bucket names ---

namespace=$(date +%s | grep -oE '.{8}$')
base_bucket_name="asr-staging-$namespace-$account_id"
template_bucket_name="$base_bucket_name-reference"
asset_bucket_name="$base_bucket_name-$region"

echo ""
echo "Generated namespace: $namespace"
echo "Template bucket:     $template_bucket_name"
echo "Asset bucket:        $asset_bucket_name"
echo ""

# --- Verify AWS credentials ---

echo "Verifying AWS credentials..."
if ! aws sts get-caller-identity --region "$region" > /dev/null 2>&1; then
    echo "ERROR: No valid AWS credentials found."
    echo "Configure credentials via 'aws configure', environment variables, or an IAM role."
    exit 1
fi
echo "AWS credentials valid. ✓"

# --- Verify Security Hub preconditions ---

echo "Checking Security Hub status..."
if ! aws securityhub describe-hub --region "$region" >/dev/null 2>&1; then
    echo "ERROR: Security Hub is not enabled in account $account_id ($region)."
    echo "Enable Security Hub before running this script."
    exit 1
fi
echo "Security Hub is enabled. ✓"

echo "Checking Security Hub admin status..."
admin_accounts=$(aws securityhub list-organization-admin-accounts --region "$region" \
    --query 'AdminAccounts[].AccountId' --output text 2>/dev/null) || {
    echo "WARNING: Could not query Security Hub admin accounts."
    echo "Make sure this account is the Organizations management or delegated admin."
}

if [ -n "${admin_accounts:-}" ]; then
    if echo "$admin_accounts" | grep -qw "$account_id"; then
        echo "Account $account_id is a Security Hub delegated admin. ✓"
    else
        echo "ERROR: Account $account_id is not a Security Hub delegated admin. ASR Admin stack must be deployed into Security Hub delegated admin account."
        exit 1
    fi
fi

echo ""

echo "Creating S3 buckets..."
if [ "$region" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$template_bucket_name" --region "$region"
    aws s3api create-bucket --bucket "$asset_bucket_name" --region "$region"
else
    aws s3api create-bucket --bucket "$template_bucket_name" --region "$region" \
        --create-bucket-configuration LocationConstraint="$region"
    aws s3api create-bucket --bucket "$asset_bucket_name" --region "$region" \
        --create-bucket-configuration LocationConstraint="$region"
fi

# Block public access
for bucket in "$template_bucket_name" "$asset_bucket_name"; do
    aws s3api put-public-access-block --bucket "$bucket" --region "$region" \
        --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
done

echo "Buckets created and public access blocked."

# --- Write config ---

cat > "$CONFIG_FILE" <<EOF
{
  "accountId": "$account_id",
  "region": "$region",
  "namespace": "$namespace",
  "baseBucketName": "$base_bucket_name",
  "templateBucketName": "$template_bucket_name",
  "assetBucketName": "$asset_bucket_name",
  "solutionName": "automated-security-response-on-aws",
  "solutionVersion": "$solution_version",
  "secHubAdminAccount": "$sechub_admin_account",
  "adminUserEmail": "$admin_user_email"
}
EOF

echo ""
echo "Config written to $CONFIG_FILE"
echo "You can now run: ./deploy-dev.sh"
