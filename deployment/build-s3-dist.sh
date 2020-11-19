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
required_cdk_version=1.68.0

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

#------------------------------------------------------------------------------
# DISABLE OVERRIDE WARNINGS
#------------------------------------------------------------------------------
# Use with care: disables the warning for overridden properties on 
# AWS Solutions Constructs
export overrideWarningsEnabled=false

#------------------------------------------------------------------------------
# Validate command line parameters
#------------------------------------------------------------------------------
# Validate command line input - must provide bucket
if [ -z "$1" ]; then 
    echo "Usage: $0 [bucket] {version}"
    echo "Please provide the base source bucket name, and version (optional). Version must be provided via a parameter or ../version.txt" 
    echo "For example: ./build-s3-dist.sh solutions v1.0.0" 
    exit 1 
fi 

# Save in environmental variables to simplify builds
bucket=$1
echo "export DIST_OUTPUT_BUCKET=$bucket" > ./setenv.sh
echo "export DIST_SOLUTION_NAME=$SOLUTION_TRADEMARKEDNAME" >> ./setenv.sh

# Version from the command line is definitive. Otherwise, use version.txt
# Note: Solutions Pipeline sends bucket name version. Command line expects bucket version
# if there is a 3rd parm then version is $3, else $2
if [ ! -z $3 ]; then
    version="$3"
elif [ ! -z "$2" ]; then
    version=$2
elif [ -e ../source/version.txt ]; then
    version=`cat ../source/version.txt`
else
    echo "Version not found. Version must be passed as argument 3 or in version.txt in the format vn.n.n"
    exit 1
fi

# Version shall start with "v"
if [[ $version != v* ]]; then
    echo prepend v to $version
    version=v$version
fi
echo "export DIST_VERSION=$version" >> ./setenv.sh

# Source ./setenv.sh to make sure we have the envs
source ./setenv.sh

echo "=========================================================================="
echo "Building $SOLUTION_NAME version $version for bucket $bucket"
echo "=========================================================================="

# Get reference for all important folders
template_dir="$PWD"
template_dist_dir="$template_dir/global-s3-assets"
build_dist_dir="$template_dir/regional-s3-assets"
source_dir="$template_dir/../source"
build_dir="$template_dir/build"     # temp build space used by unit test
temp_work_dir="${template_dir}/temp"

echo "------------------------------------------------------------------------------"
echo "[Init] Clean old dist, node_modules and bower_components folders"
echo "------------------------------------------------------------------------------"
do_cmd rm -rf $template_dist_dir
do_cmd mkdir -p $template_dist_dir
do_cmd rm -rf $build_dist_dir
do_cmd mkdir -p $build_dist_dir
do_cmd rm -rf $build_dir
do_cmd mkdir -p $build_dir
do_cmd rm -rf $temp_work_dir
do_cmd mkdir -p $temp_work_dir

echo "------------------------------------------------------------------------------"
echo "[Copy] Copy source to temp and remove unwanted files"
echo "------------------------------------------------------------------------------"
do_cmd cp -r $source_dir $temp_work_dir # make a copy to work from
cd $temp_work_dir
# remove node_modules
find . -name node_modules | while read file;do rm -rf $file; done
# remove package-lock.json
find . -name package-lock.json | while read file;do rm $file; done

echo "------------------------------------------------------------------------------"
echo "[Install] CDK"
echo "------------------------------------------------------------------------------"

# install typescript once so we can build each of the packages below
# If this must be done for the pipeline then we need to figure out how to detect
# command-line (user) build so as not to do global install (requires root/sudo)
# npm install -g typescript
# 
cd $temp_work_dir/source/solution_deploy
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
echo "[Pack] Custom Action Lambda"
echo "------------------------------------------------------------------------------"
cd $template_dir
pip install -r ./requirements.txt -t $temp_work_dir/source/solution_deploy/source
cd $temp_work_dir/source/solution_deploy/source
mkdir ${build_dist_dir}/lambda
zip --recurse-paths ${build_dist_dir}/lambda/createCustomAction.py.zip createCustomAction.py lib/* requests/* chardet/* certifi/* idna/* urllib3/*

echo "------------------------------------------------------------------------------"
echo "[Create] Playbook Templates - CIS"
echo "------------------------------------------------------------------------------"
mkdir -p ${build_dist_dir}/playbooks/CIS
mkdir -p ${template_dist_dir}/playbooks

# install npm locally in playbooks/core
cd $temp_work_dir/source/playbooks/core
npm install -s

# Install npm for the compliance pack:
do_cmd cd $temp_work_dir/source/playbooks/CIS
do_cmd npm install -s
do_cmd npm run build

# Create the template for the compliance pack
cdk --no-version-reporting synth CisStack > $template_dist_dir/playbooks/CIS.template 
cdk --no-version-reporting synth CisPermissionsStack > $template_dist_dir/playbooks/CISPermissions.template 

if [[ -d ./lambda ]]; then
    do_cmd mkdir -p ${build_dir}/playbooks/CIS/tests  # output directory
    do_cmd mkdir -p ${build_dir}/playbooks/CIS/lib
    do_cmd cp lambda/*.py ${build_dir}/playbooks/CIS
    do_cmd cp -R lambda/tests/* ${build_dir}/playbooks/CIS/tests
    # All playbooks get all libs. This is OK right now, but may need to be
    # more specific later.
    do_cmd cp -R $temp_work_dir/source/playbooks/python_lib/* ${build_dir}/playbooks/CIS/lib
    do_cmd cp -R $temp_work_dir/source/playbooks/python_tests/* ${build_dir}/playbooks/CIS/tests
    do_cmd cp -R ${temp_work_dir}/source/solution_deploy/source/requests ${build_dir}/playbooks/CIS/
    do_cmd cp -R ${temp_work_dir}/source/solution_deploy/source/urllib3 ${build_dir}/playbooks/CIS/
    do_cmd cp -R ${temp_work_dir}/source/solution_deploy/source/chardet ${build_dir}/playbooks/CIS/
    do_cmd cp -R ${temp_work_dir}/source/solution_deploy/source/certifi ${build_dir}/playbooks/CIS/
    do_cmd cp -R ${temp_work_dir}/source/solution_deploy/source/idna ${build_dir}/playbooks/CIS/
    rm -rf ${build_dir}/playbooks/CIS/lib/__pycache__/

    cd ${build_dir}/playbooks/CIS
    for lambda in *.py; do
        do_cmd zip -q --recurse-paths ${build_dist_dir}/playbooks/CIS/${lambda}.zip $lambda lib requests/* chardet/* certifi/* idna/* urllib3/*
    done
fi

cd ${template_dir}

echo "------------------------------------------------------------------------------"
echo "[Create] Deployment Templates"
echo "------------------------------------------------------------------------------"
# Don't build the deployment template until AFTER the playbooks
cd $temp_work_dir/source/solution_deploy

# Output YAML - this is currently the only way to do this for multiple templates
for template in `cdk ls`; do
    echo Create template $template
    # do_cmd npm run build
    cdk --no-version-reporting synth $template -c solutionId=$SOLUTION_ID > ${template_dist_dir}/${template}.template
done
cd ${template_dir}

[ -e ${template_dir}/*.template ] && do_cmd cp $template_dir/*.template $template_dist_dir/

# Rename SolutionDeployStack.template
mv ${template_dist_dir}/SolutionDeployStack.template ${template_dist_dir}/aws-sharr-deploy.template
mv ${template_dist_dir}/ServiceCatalogStack.template ${template_dist_dir}/aws-sharr-portolio-deploy.template

echo Build Complete
