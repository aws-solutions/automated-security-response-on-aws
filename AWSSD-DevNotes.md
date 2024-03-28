# SHARR v1.3.0

## How it works

- Security Hub Custom Actions send selected finding events to CloudWatch Logs
- EventBridge rules matching SHARR-supported findings send the findings to the SHARR Orchestrator
- The Orchestrator, an AWS Step Function, uses finding data to determine which account and remediation to execute, verifies that the remediation is active in that account, executes it, and monitors until completion.

### SSM Parameters
There are N parameters that control processing under /Solutions/SO0111:
CMK_ARN - encryption key for the AWS FSBP runbooks
CMK_ARN - Admin account only, KMS key for solution encryption
SNS_Topic_Arn - arn of the SHARR topic
sendAnonymizedMetrics - controls whether the solution sends metrics
version - solution version

The following are set by each Security Standard's playbook, enabling remediation mapping in the step function:
\<security standard\>/shortname - 1-12 character abbreviation for the security standard. Ex. CIS
\<security standard\>/\<version\> - 'enabled' if this version of the standard is enabled.

# Create problems for Sec Hub to find

-   Create keys

-   Create IAM accounts with weak passwords

-   Make sure CloudTrail is enabled but without log file validation

-   Create a public CloudTrail bucket

-   Make sure there is no access logging on CloudTrail bucket

-   Create KMS CMK with no key rotation

-   CIS_2-9: "Remediates CIS 2.9 by enabling reject filtered VPC flow logging
    for VPCs without it"

-   Create VPCs and subnets. Create an EC2 instance with SSH and RDP open

-   Create a default security group that has open ports

### CloudTrail

#### Admin

-   Multi-region

-   Validation NOT selected

-   NOT encrypted

-   Stored to s3://sechubauto-admin

#### Member 1

-   NOT enabled

#### Member 2

-   Enabled

-   Single region

-   Stored to s3://sechubauto-member2

#### Member 3

KMS Key: cloudtrailkey

-   Multi-region

-   Encrypted

#### Member 4

-   Default state for testing

-   Use this account for auto-remediation

### AWS Config

Need to enable AWS Config on all 5 accounts

# Testing

### 1) Create the basic stack using template SolutionDeploy.template from the solution-reference bucket.

-   Creates CloudWatch Logs LogGroup

-   Creates Service Catalog Portfolio

-   Creates Service Catalog Product for each Playbook

### 2) Deploy a playbook

-   Grant access to a role to the Portfolio

-   Verify that you have access to the Product via the role

-   Deploy a playbook

-   Verify that the playbook deploys correctly (should take only a few minutes):

    -   Creates a lambda

    -   Creates a CloudWatch Event Rule that triggers the Lambda

    -   Creates a Security Hub Custom Action that triggers the Lambda

### 3) Test the playbook

-   Verify it produces the expected results

-   Verify logging to CloudWatch LogGroup "SHARR"

    -   Note: Lambda logs to the usual CW Logs prefix. Application data is
        logged to SHARR.

-   Verify that remediated findings' workflow status is updated

### 4) Update the solution

-   Make a change to a Playbook Lambda

-   Change the version_description.txt for the lambda

-   Build a new version

-   Update the existing stack to the new version

-   Verify that it deploys successfully

-   Verify that the Version description in the Service Catalog product matches
    version_description.txt (note that the version is replaced rather than a new
    version created)

-   Verify that each playbook’s version number has updated

    -   This is the current behavior. It may change in the next release

### 5) Update the playbook

-   Update the playbook product deployed earlier

-   Verify that the Lambda updates

-   Verify again that it works correctly

### 6) Remove the Playbook

-   Use Service Catalog to terminate a playbook

-   Verify that the Custom Action is removed from Security Hub

-   Verify that the CW Event rule is removed

-   Verify that the Lambda is removed

# Notes

One app generates multiple templates.

Customer deploys our published solution from a template.

Customer can deploy from GitHub using CDK and our build-s3-dist.sh script.

Once you associate principals with a Portfolio you can no longer delete the
solution template.

ServiceCatalog does not appear to support option to retain the portfolio on
template deletion

# Links

[Getting
Started](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html)
[AWS Security Findings Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)

[Incident Response white paper](https://aws.amazon.com/blogs/security/how-to-perform-automated-incident-response-multi-account-environment/)
