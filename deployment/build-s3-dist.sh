#!/bin/bash
#
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

# Important: CDK global version number
# This controls the CDK and AWS Solutions Constructs version. Solutions
# Constructs versions map 1:1 to CDK versions. When setting this value,
# choose the latest AWS Solutions Constructs version.
required_cdk_version=1.155.0

# Get reference for all important folders
template_dir="$PWD"
template_dist_dir="$template_dir/global-s3-assets"
build_dist_dir="$template_dir/regional-s3-assets"
source_dir="../source"
temp_work_dir="${template_dir}/temp"

# Functions to reduce repetitive code
# do_cmd will exit if the command has a non-zero return code.
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

clean() {
    echo "------------------------------------------------------------------------------"
    echo "[Init] Clean old dist, node_modules and bower_components folders"
    echo "------------------------------------------------------------------------------"
    do_cmd rm -rf $template_dist_dir
    do_cmd rm -rf $build_dist_dir
    do_cmd rm -rf $temp_work_dir
    do_cmd rm -rf ${template_dir}/${source_dir}/node_modules
    cd $source_dir
    # remove node_modules
    find . -name node_modules | while read file;do rm -rf $file; done
    cd $template_dir
}

#------------------------------------------------------------------------------
# Validate command line parameters
#------------------------------------------------------------------------------
# Validate command line input - must provide bucket
# Command line from the buildspec is, by convention:
# chmod +x ./build-s3-dist.sh && ./build-s3-dist.sh $DIST_OUTPUT_BUCKET $SOLUTION_NAME $VERSION $DEVBUILD

while getopts ":b:v:tch" opt;
do
    case "${opt}" in
        b ) bucket=${OPTARG};;
        v ) version=${OPTARG};;
        t ) devtest=1;;
        c)
            clean
            exit 0
            ;;
        *)
            echo "Usage: $0 -b <bucket> [-v <version>] [-t]"
            echo "Version must be provided via a parameter or ../version.txt. Others are optional."
            echo "-t indicates this is a pre-prod build and instructs the build to use a non-prod Solution ID, DEV-SOxxxx"
            echo "Production example: ./build-s3-dist.sh -b solutions -v v1.0.0"
            echo "Dev example: ./build-s3-dist.sh -b solutions -v v1.0.0 -t"
            exit 1
            ;;
    esac
done

#------------------------------------------------------------------------------
# DISABLE OVERRIDE WARNINGS
#------------------------------------------------------------------------------
# Use with care: disables the warning for overridden properties on
# AWS Solutions Constructs
export overrideWarningsEnabled=false

# Save in environmental variables to simplify builds
echo "export DIST_OUTPUT_BUCKET=$bucket" > ./setenv.sh

# Version from the command line is definitive. Otherwise, use version.txt
if [[ ! -z "$version" ]]; then
    echo Version is $version from the command line
elif ( command -v jq ) && [[ -f ${template_dir}/${source_dir}/package.json ]]; then
    version=`cat ${template_dir}/${source_dir}/package.json | jq -r .version`
elif [[ -e ../source/version.txt ]]; then
    version=`cat ../source/version.txt`
    echo Version is $version from ../source/version.txt
else
    echo "Version not found. Version must be specified in the command line parameter -v or in version.txt in the format vn.n.n"
    exit 1
fi

# Version shall start with "v"
if [[ $version != v* ]]; then
    echo prepend v to $version
    version=v$version
fi
echo "export DIST_VERSION=$version" >> ./setenv.sh

#------------------------------------------------------------------------------
# READ STORED CONFIG
#------------------------------------------------------------------------------
# solution_env.sh must exist in the solution root. It is the definitive source
# for solution ID, name, and trademarked name
#
# It takes precedence over the command line (oddly backwards, but to prevent
# errors)
#
# Ex:
# #!/bin/bash
# SOLUTION_ID='SO0111'
# SOLUTION_NAME='AWS Security Hub Automated Response & Remediation'
# SOLUTION_TRADEMARKEDNAME='aws-security-hub-automated-response-and-remediation'
#
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
    if [[ ! -z $devtest ]]; then
        SOLUTION_ID=DEV-$SOLUTION_ID
    fi
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
    echo "export DIST_SOLUTION_NAME=$SOLUTION_TRADEMARKEDNAME" >> ./setenv.sh
fi
# Source ./setenv.sh to make sure we have the envs
source ./setenv.sh

echo "=========================================================================="
echo "Building $SOLUTION_NAME ($SOLUTION_ID) version $version for bucket $bucket"
echo "=========================================================================="

clean

echo "------------------------------------------------------------------------------"
echo "[Init] Create folders"
echo "------------------------------------------------------------------------------"
do_cmd mkdir -p $template_dist_dir
do_cmd mkdir -p $build_dist_dir
do_cmd mkdir -p $temp_work_dir
do_cmd mkdir ${build_dist_dir}/lambda
do_cmd mkdir -p ${template_dist_dir}/playbooks

echo "------------------------------------------------------------------------------"
echo "[Install] CDK"
echo "------------------------------------------------------------------------------"

# cd $temp_work_dir/source
cd $source_dir
do_cmd npm install      # local install per package.json
do_cmd npm install aws-cdk@$required_cdk_version
export PATH=$(npm bin):$PATH
# Check cdk version
cdkver=`cdk --version | grep -Eo '^[0-9]{1,2}\.[0-9]+\.[0-9]+'`
echo CDK version $cdkver
if [[ $cdkver != $required_cdk_version ]]; then
    echo Required CDK version is $required_cdk_version, found $cdkver
    exit 255
fi
do_cmd npm run build       # build javascript from typescript

echo "------------------------------------------------------------------------------"
echo "[Pack] Lambda Layer (used by playbooks)"
echo "------------------------------------------------------------------------------"
cd $template_dir
do_cmd cp -r $source_dir $temp_work_dir # make a copy to work from
cd $temp_work_dir
# remove node_modules
find . -name node_modules | while read file;do rm -rf $file; done
# remove package-lock.json
find . -name package-lock.json | while read file;do rm $file; done

mkdir -p $temp_work_dir/source/solution_deploy/lambdalayer/python
cp ${template_dir}/${source_dir}/LambdaLayers/*.py $temp_work_dir/source/solution_deploy/lambdalayer/python
do_cmd pip install -r $template_dir/requirements.txt -t $temp_work_dir/source/solution_deploy/lambdalayer/python
cd $temp_work_dir/source/solution_deploy/lambdalayer
zip --recurse-paths ${build_dist_dir}/lambda/layer.zip python

echo "------------------------------------------------------------------------------"
echo "[Pack] Member Stack Lambda Layer (used by custom resources)"
echo "------------------------------------------------------------------------------"
do_cmd mkdir -p $temp_work_dir/source/solution_deploy/memberlambdalayer/python
do_cmd cp ${template_dir}/${source_dir}/LambdaLayers/cfnresponse.py $temp_work_dir/source/solution_deploy/memberlambdalayer/python
do_cmd cp ${template_dir}/${source_dir}/LambdaLayers/logger.py $temp_work_dir/source/solution_deploy/memberlambdalayer/python
do_cmd cd $temp_work_dir/source/solution_deploy/memberlambdalayer
do_cmd zip --recurse-paths ${build_dist_dir}/lambda/memberLayer.zip python

echo "------------------------------------------------------------------------------"
echo "[Pack] Custom Action Lambda"
echo "------------------------------------------------------------------------------"
cd $template_dir
cd $temp_work_dir/source/solution_deploy/source
zip ${build_dist_dir}/lambda/createCustomAction.py.zip createCustomAction.py
# Copy LambdaLayer modules in preparation for running tests
# These are not packaged with the Lambda
do_cmd cp ../../LambdaLayers/*.py .

echo "------------------------------------------------------------------------------"
echo "[Pack] Updatable Runbook Provider Lambda"
echo "------------------------------------------------------------------------------"
do_cmd cd $temp_work_dir/source/solution_deploy/source
do_cmd zip ${build_dist_dir}/lambda/updatableRunbookProvider.py.zip updatableRunbookProvider.py

echo "------------------------------------------------------------------------------"
echo "[Pack] Orchestrator Lambdas"
echo "------------------------------------------------------------------------------"
# cd $template_dir
cd $temp_work_dir/source/Orchestrator
ls | while read file; do
    if [ ! -d $file ]; then
        zip ${build_dist_dir}/lambda/${file}.zip ${file}
    fi
done
# Copy LambdaLayer modules in preparation for running tests
# These are not packaged with the Lambda
do_cmd cp ../LambdaLayers/*.py .

echo "------------------------------------------------------------------------------"
echo "[Create] Playbooks"
echo "------------------------------------------------------------------------------"
for playbook in `ls ${template_dir}/${source_dir}/playbooks`; do
    if [ $playbook == 'NEWPLAYBOOK' ] || [ $playbook == '.coverage' ] || [ $playbook == 'common' ]; then
        continue
    fi
    echo Create $playbook playbook
    do_cmd cd ${template_dir}/${source_dir}/playbooks/${playbook}
        for template in `cdk list`; do
        echo Create $playbook template $template
        # do_cmd npm run build
        cdk --no-version-reporting synth $template > ${template_dist_dir}/playbooks/${template}.template
    done
done

echo "------------------------------------------------------------------------------"
echo "[Create] Deployment Templates"
echo "------------------------------------------------------------------------------"
# Don't build the deployment template until AFTER the playbooks
cd ${template_dir}/${source_dir}/solution_deploy

# Output YAML - this is currently the only way to do this for multiple templates
for template in `cdk ls`; do
    echo Create template $template
    cdk --no-version-reporting synth $template > ${template_dist_dir}/${template}.template
done
cd ${template_dir}

[ -e ${template_dir}/*.template ] && do_cmd cp $template_dir/*.template $template_dist_dir/

# Rename SolutionDeployStack.template
mv ${template_dist_dir}/SolutionDeployStack.template ${template_dist_dir}/aws-sharr-deploy.template
mv ${template_dist_dir}/MemberStack.template ${template_dist_dir}/aws-sharr-member.template
mv ${template_dist_dir}/RunbookStack.template ${template_dist_dir}/aws-sharr-remediations.template
mv ${template_dist_dir}/OrchestratorLogStack.template ${template_dist_dir}/aws-sharr-orchestrator-log.template
mv ${template_dist_dir}/MemberRoleStack.template ${template_dist_dir}/aws-sharr-member-roles.template

echo Build Complete
