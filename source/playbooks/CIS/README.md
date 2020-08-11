# CIS Playbooks
aws-security-hub-automated-response-and-remediation solution CIS playbook creates the necessary AWS resources for remediating CIS Rule findings listed below,
```
CIS 1.3 - 1.4
    [CIS.1.3] Ensure credentials unused for 90 days or greater are disabled
    [CIS.1.4] Ensure access keys are rotated every 90 days or less
CIS 1.5 - 1.11
    [CIS.1.5] Ensure IAM password policy requires at least one uppercase letter
    [CIS.1.6] Ensure IAM password policy requires at least one lowercase letter
    [CIS.1.7] Ensure IAM password policy requires at least one symbol
    [CIS.1.8] Ensure IAM password policy requires at least one number
    [CIS.1.9] Ensure IAM password policy requires minimum password length of 14 or greater
    [CIS.1.10] Ensure IAM password policy prevents password reuse
    [CIS.1.11] Ensure IAM password policy expires passwords within 90 days or less
CIS 2.2
    [CIS.2.2] Ensure CloudTrail log file validation is enabled
CIS 2.3
    [CIS.2.3] Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible
CIS 2.4
    [CIS.2.4] Ensure CloudTrail trails are integrated with CloudWatch Logs
CIS 2.6
    [CIS.2.6] Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
CIS 2.8
    [CIS.2.8] Ensure rotation for customer created CMKs is enabled
CIS 2.9
    [CIS.2.9] Ensure VPC flow logging is enabled in all VPCs
CIS 4.1 - 4.2
    [CIS.4.1] Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
    [CIS.4.2] Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
CIS 4.3
    [CIS.4.3] Ensure the default security group of every VPC restricts all traffic
```

Each playbook creates the following AWS resources,
* Custom Action in AWS Security Hub
* AWS Lambda for remediation
* AWS CloudWatch Event rule for custom action and automated trigger
* AWS CloudWatch Log group for each set of CIS rule(s)

CIS playbook module is built using AWS CDK, each CIS rule(s) can be further customized if required.

## Source Code Organization
CIS module is a Node JS project, based on AWS CDK. Following are the preqequisites for the module
* NODE JS 
* AWS CDK (https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html#getting_started_prerequisites)
* Typescript (Components which generate the cloudformation templates utilize CDK API's in Typescript, the playbook Lambda Functions use Python 3.7+)

## Commands
* npm install (Install the node module dependencies)
* npm run build (Create Javascript binaries from Typescript)
* cdk synth (After CDK is installed CDK CLI can be used to generate the cloudformation stack YAML/JSON format, Refer CDK Documentation for detailed information on the features and how to work with AWS CDK Contructs https://docs.aws.amazon.com/cdk/latest/guide/work-with.html)

