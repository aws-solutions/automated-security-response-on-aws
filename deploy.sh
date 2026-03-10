#!/bin/bash
# ./deploy.sh uat v2.1.3.7
# ./deploy.sh prod v2.1.3.7
# Get environment argument (defaults to empty string if not provided)
ENV=${1:-""}

# Get version argument (defaults to v2.1.3.7 if not provided)
VERSION=${2:-"v2.1.3.7"}

# Determine S3 bucket name based on environment
if [ "$ENV" = "prod" ]; then
    BUCKET_NAME="5pillars-prod-playbooks"
elif [ "$ENV" = "uat" ] || [ "$ENV" = "" ]; then
    BUCKET_NAME="5pillars-uat-playbooks"
else
    echo "Error: Invalid environment argument. Use empty string, 'uat', or 'prod'"
    exit 1
fi

echo "Deploying to environment: ${ENV:-uat (default)}"
echo "Using S3 bucket: $BUCKET_NAME"
echo "Using version: $VERSION"

cd deployment
chmod +x ./build-s3-dist.sh
./build-s3-dist.sh -b $BUCKET_NAME -c $VERSION
./build-s3-dist.sh -b $BUCKET_NAME -v $VERSION
chmod +x ./upload-s3-dist.sh
./upload-s3-dist.sh ap-southeast-1
./upload-s3-dist.sh ap-southeast-2
./upload-s3-dist.sh ap-southeast-4
./upload-s3-dist.sh ap-northeast-1
./upload-s3-dist.sh ap-south-1
./upload-s3-dist.sh us-east-1
./upload-s3-dist.sh us-east-2
./upload-s3-dist.sh us-west-1
./upload-s3-dist.sh us-west-2
./upload-s3-dist.sh eu-west-1
./upload-s3-dist.sh eu-west-2
./upload-s3-dist.sh eu-central-1
