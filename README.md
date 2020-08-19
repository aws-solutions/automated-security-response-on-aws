# AWS Security Hub Automated Response and Remediation (ID SO0111)

AWS Security Hub Automated Response and Remediation is an add-on solution that enables AWS Security Hub customers to remediate security findings with a single click using predefined response and remediation actions called “Playbooks”. Alternately the playbooks can also be configured to remediate findings in AWS Security Hub automatically. The remediation is performed using AWS Lambda and in some cases using AWS Systems Manager, the playbooks execute steps to remediate security issues, such as unused keys, open security groups, password policies, VPC configurations and public S3 buckets. The solution contains the playbook remediations for some of the security standards defined as part of CIS AWS Foundations Benchmark v1.2.0.

## Getting Started
To get started with the AWS Security Hub Automated Response and Remediation, please review the solution documentation. https://aws.amazon.com/solutions/implementations/aws-security-hub-automated-response-and-remediation/

## Building from GitHub

### Overview of the Process

Building from GitHub source will allow you to modify the solution, such as adding custom actions or upgrading to a new release. The process consists of downloading the source from GitHub, creating buckets to be used for deployment, building the solution, and uploading the artifacts needed for deployment.

#### You will need:

* a Linux client with the AWS CLI v2 installed and python 3.7+, AWS CDK
* source code downloaded from GitHub
* two S3 buckets (minimum): 1 global and 1 for each region where you will deploy

### Download from GitHub

Clone or download the repository to a local directory on your linux client. Note: if you intend to modify Ops Automator you may wish to create your own fork of the GitHub repo and work from that. This allows you to check in any changes you make to your private copy of the solution.

**Git Clone example:**

```
git clone https://github.com/awslabs/aws-security-hub-automated-response-and-remediation.git
```

**Download Zip example:**
```
wget https://github.com/awslabs/aws-security-hub-automated-response-and-remediation/archive/master.zip
```

#### Repository Organization
aws-security-hub-automated-response-and-remediation uses AWS CDK for generating the cloudformation templates.
```
|-source/
  |-playbooks                    [ Playbooks CloudDevelopment Kit Code and lambda source code]
    |- core/                     [ Cloud Development Kit common node module ]
    |- CIS/                      [ CIS playbook code ]
    |- python_lib/               [ Python libraries used in the lambda source code in CIS playbooks ]
    |- python_tests/             [ Python unit tests for libraries used in the lambda source code ]
  |-solution_deploy              [ Solution Cloud Development Kit node module ]
```

### Build

AWS Solutions use two buckets: a bucket for global access to templates, which is accessed via HTTPS, and regional buckets for access to assets within the region, such as Lambda code. You will need:

* One global bucket that is access via the http end point. AWS CloudFormation templates are stored here. Ex. "mybucket"
* One regional bucket for each region where you plan to deploy using the name of the global bucket as the root, and suffixed with the region name. Ex. "mybucket-us-east-1"
* Your buckets should be encrypted and disallow public access

**Build the solution**

From the *deployment* folder in your cloned repo, run build-s3-dist.sh, passing the root name of your bucket (ex. mybucket) and the version you are building (ex. v1.0.0). We recommend using a semver version based on the version downloaded from GitHub (ex. GitHub: v1.0.0, your build: v1.0.0.mybuild)

```
chmod +x build-s3-dist.sh
build-s3-dist.sh <bucketname> <version>
```

**Run Unit Tests**

```
cd ./deployment
chmod +x ./run-unit-tests.sh
./run-unit-tests.sh
```

Confirm that all unit tests pass.

**Upload to your buckets**

Run upload_s3_dist.sh, passing the name of the region where you want to deploy the solution (ex. us-east-1). Note that this prepares your templates for deployment, but does not do the actual deployment in your account.
```
cd ./deployment
./upload_s3_dist.sh <region>
```

## Deploy

See the (AWS Security Hub Automated Response and Remediation Implementation Guide)[http://link] for deployment instructions, using the link to the SolutionDeployStack.template from your bucket, rather than the one for AWS Solutions. Ex. https://mybucket.s3.amazonaws.com/aws-security-hub-automated-response-and-remediation/v1.0.0.mybuild/aws-sharr-deploy.template

Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://www.apache.org/licenses/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
