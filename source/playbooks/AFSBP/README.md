# AFSBP Playbook

aws-security-hub-automated-response-and-remediation solution AWS Foundational Security Best Practices (AFSBP) playbook creates the necessary AWS resources for remediating selected AFSBP findings. See the Implementation Guide for details.

Each playbook creates the following AWS resources,
* Custom Action in AWS Security Hub
* AWS Lambda Step Function for processing incoming Findings
* AWS Systems Manager Runbooks for performing remediations
* AWS CloudWatch Event rule for custom action and automated trigger
* AWS CloudWatch Log group for each set of AFSBP Control
