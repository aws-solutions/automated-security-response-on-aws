#!/usr/bin/env bash
# 
# This assumes build-s3-dist.sh has run successfully in the same shell environment. 
# The following environmental variables are set by build-s3-dist.sh and used by this 
# script:
#
# $DIST_OUTPUT_BUCKET global/root bucket name
# $DIST_SOLUTION_NAME solution name
# $DIST_VERSION version of the solution
# 
# This script should be run from the repo's deployment directory 
# cd deployment 
# ./upload-s3-dist.sh
# 
function do_cmd { 
    echo "------ EXEC $*" 
    $* 
}

function do_replace { 
    replace="s/$2/$3/g" 
    file=$1 
    do_cmd sed -i -e $replace $file 
} 

if [ -z "$1" ]; then
    echo "You must specify a region to deploy to. Ex. us-east-1"
    exit 1
else
    region=$1
fi

if [ -e "./setenv.sh" ]; then
    source ./setenv.sh
else    
    echo "build-s3-dist.sh must be run immediately prior to this script. Please (re)run build-s3-dist.sh, then try again."
fi

if [ -z "$DIST_OUTPUT_BUCKET" ] | [ -z "$DIST_SOLUTION_NAME" ] | [ -z "$DIST_VERSION" ]; then 
	echo "build-s3-dist.sh must be run immediately prior to this script. Please (re)run build-s3-dist.sh, then try again."
    exit 1 
fi 

bucket=$DIST_OUTPUT_BUCKET
solution_name=$DIST_SOLUTION_NAME
version=$DIST_VERSION

# Test the AWS CLI
caller=`aws sts get-caller-identity`
status=$?
if [ $status != 0 ]; then
    echo "The AWS CLI is not present or not configured."
    exit 1
fi

# Validate region
region_check=`aws ec2 describe-regions --region $region | grep ec2.$region.amazonaws.com | wc -l`
status=$?
if [ $status != 0 ] | [ $region_check != 1 ]; then
    echo "$region is not a valid AWS region name."
    exit 1
fi

bucket_state=`aws s3 ls s3://$bucket`
status=$?
if [ $status != 0 ]; then
    echo "Bucket $bucket does not exist. Please see README.md"
    exit 1
fi

bucket_state=`aws s3 ls s3://$bucket-$region`
status=$?
if [ $status != 0 ]; then
    echo "Bucket $bucket-$region does not exist. Please see README.md"
    exit 1
fi

echo "=========================================================================="
echo "Deploying $solution_name version $version to bucket $bucket-$region"
echo "=========================================================================="
echo "Templates: $bucket/$solution_name/$version/"
echo "Lambda code: $bucket-$region/$solution_name/$version/"
echo "---"

# read -p "Press [Enter] key to start upload to $region"

aws s3 sync ./global-s3-assets s3://$bucket/$solution_name/$version/
aws s3 sync ./regional-s3-assets s3://$bucket-$region/$solution_name/$version/

echo "Completed uploading distribution. You may now install from the templates in $bucket/$solution_name/$version/"
