[🚀 Solution Landing
Page](https://aws.amazon.com/solutions/implementations/aws-security-hub-automated-response-and-remediation/)
\| [🚧 Feature
request](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation/issues/new?assignees=&labels=feature-request%2C+enhancement&template=feature_request.md&title=)
\| [🐛 Bug
Report](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation%3E/issues/new?assignees=&labels=bug%2C+triage&template=bug_report.md&title=)

Note: If you want to use the solution without building from source, navigate to
Solution Landing Page

## Table of contents

- [Solution Overview](#solution-overview)
- [Architecture Diagram](#architecture-diagram)
- [AWS CDK Constructs](#aws-solutions-constructs)
- [Customizing the Solution](#customizing-the-solution)
    - [Prerequisites for Customization](#prerequisites-for-customization)
    - [Build](#build)
    - [Unit Test](#unit-test)
    - [Deploy](#deploy)
- [File Structure](#file-structure)
- [License](#license)

<a name="solution-overview"></a>
# Solution Overview

AWS Security Hub Automated Response and Remediation is an add-on solution that
enables AWS Security Hub customers to remediate security findings with a single
click using predefined response and remediation actions called “Playbooks”.
Alternately the playbooks can also be configured to remediate findings in AWS
Security Hub automatically. The remediation is performed using AWS Lambda and in
some cases using AWS Systems Manager, the playbooks execute steps to remediate
security issues, such as unused keys, open security groups, password policies,
VPC configurations and public S3 buckets. The solution contains the playbook
remediations for some of the security standards defined as part of CIS AWS
Foundations Benchmark v1.2.0 and for AWS Foundational Security Best Practices
v1.0.0.

<a name="architecture-diagram"></a>
# Architecture Diagram

![](./SHARR_v1.2.jpg)

<a name="aws-solutions-constructs"></a>
# AWS Solutions Constructs
* aws-events-rule-lambda - creates event rules that trigger the appropriate remediation, as well as any necessary permissions.

<a name="customizing-the-solution"></a>
# Customizing the Solution

**Note**: Customization of AWS Security Hub Automated Response and Remediation is not yet documented. If your goal is just to deploy the solution, please use the template on the [AWS Security Hub Automated Response and Remediation Landing Page](https://aws.amazon.com/solutions/implementations/aws-security-hub-automated-response-and-remediation/). *There is no need to build the solution from source.*

If you choose to continue, please be aware that reading and adjusting the source code will be necessary.

<a name="prerequisites-for-customization"></a>
## Prerequisites for Customization

* a Linux client with the AWS CLI v2 installed and python 3.7+, AWS CDK
* source code downloaded from GitHub
* two S3 buckets (minimum): 1 global and 1 for each region where you will deploy
  * An Amazon S3 Bucket for solution templates - accessed globally via https.
  * An Amazon S3 Bucket for source code - regional.

<a name="build"></a>
## Build

Building from GitHub source will allow you to modify the solution, such as adding custom actions or upgrading to a new release. The process consists of downloading the source from GitHub, creating buckets to be used for deployment, building the solution, and uploading the artifacts needed for deployment.

Clone or download the repository to a local directory on your linux client. Note: if you intend to modify the solution you may wish to create your own fork of the GitHub repo and work from that. This allows you to check in any changes you make to your private copy of the solution.

**Git Clone example:**

```
git clone https://github.com/awslabs/aws-security-hub-automated-response-and-remediation.git
```

**Download Zip example:**
```
wget https://github.com/awslabs/aws-security-hub-automated-response-and-remediation/archive/master.zip
```

AWS Solutions use two buckets: a bucket for global access to templates, which is accessed via HTTPS, and regional buckets for access to assets within the region, such as Lambda code. You will need:

* One global bucket that is access via the http end point. AWS CloudFormation templates are stored here. Ex. "mybucket"
* One regional bucket for each region where you plan to deploy using the name of the global bucket as the root, and suffixed with the region name. Ex. "mybucket-us-east-1"
* Your buckets should be encrypted and disallow public access

**NOTE**: When creating your buckets, ensure they are not publicly accessible. Use random bucket names. Disable public access. Use KMS encryption. And verify bucket ownership before uploading.

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

**NOTE**: Verify bucket ownership before uploading.
---

By default, the templates created by build-s3-dist.sh expect the software to be stored in **aws-security-hub-automated-response-and-remediation/v\<version\>**. If in doubt, view the template.

Use a tool such as the AWS S3 CLI "sync" command to upload your templates to the reference bucket and code to the regional bucket.

<a name="deploy"></a>
## Deploy

See the [AWS Security Hub Automated Response and Remediation Implementation Guide](https://docs.aws.amazon.com/solutions/latest/aws-security-hub-automated-response-and-remediation/welcome.html) for deployment instructions, using the link to the SolutionDeployStack.template from your bucket, rather than the one for AWS Solutions. Ex. https://mybucket-reference.s3.amazonaws.com/aws-security-hub-automated-response-and-remediation/v1.0.0.mybuild/aws-sharr-deploy.template

<a name="file-structure"></a>
# File structure

aws-security-hub-automated-response-and-remediation uses AWS CDK for generating the cloudformation templates.
<pre>
|-source/
  |-playbooks                    [ Playbooks CloudDevelopment Kit Code and lambda source code]
    |- core/                     [ Cloud Development Kit common node module ]
    |- CIS/                      [ CIS playbook code ]
    |- python_lib/               [ Python libraries used in the lambda source code in CIS playbooks ]
    |- python_tests/             [ Python unit tests for libraries used in the lambda source code ]
  |-solution_deploy              [ Solution Cloud Development Kit node module ]
</pre>

<a name="license"></a>
# License

See license
[here](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation/blob/master/LICENSE.txt)

# Collection of operational metrics
This solution collects anonymous operational metrics to help AWS improve the
quality of features of the solution. For more information, including how to disable
this capability, please see the
[Implementation Guide](https://docs.aws.amazon.com/solutions/latest/aws-security-hub-automated-response-and-remediation/collection-of-operational-metrics.html)
