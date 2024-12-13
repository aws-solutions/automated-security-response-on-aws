# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2024-12-16

### Added

- Option to integrate an external ticket system by providing a lambda function name at deployment time
- Integration stacks for Jira and ServiceNow as external ticketing systems
- Widget "Total successful remediations" on the CloudWatch Dashboard
- Detailed success/failure metrics on the CloudWatch Dashboard grouped by control id
- Detailed log of account management actions taken by ASR on the CloudWatch Dashboard
- Remediations for additional control ids
- Playbook for CIS 3.0 standard
- Integrated Poetry for python dependency management
- Integration with AWS Lambda Powertools Logger & Tracer
- Deletion protection and autoscaling to scheduling table

### Changed

- More detailed notifications
- Added namespace to member roles to avoid name conflicts when reinstalling the solution
- Removed CloudFormation retention policies for member IAM roles where unnecessary

### Fixed

- Config.1 remediation script to allow non-"default" Config recorder name
- parse_non_string_types.py script to allow boolean values


## [2.1.4] - 2024-11-18

### Changed

- Upgraded python runtimes in all control runbooks from python3.8 to python3.11.
  - Upgrade is done at build-time temporarily, until the `cdklabs/cdk-ssm-documents` package adds support for newer python runtimes.

### Security

- Upgraded cross-spawn to mitigate [CVE-2024-21538](https://avd.aquasec.com/nvd/cve-2024-21538)

## [2.1.3] - 2024-09-18

### Fixed

- Resolved an issue in the remediation scripts for EC2.18 and EC2.19 where security group rules with IpProtocol set to "-1" were being incorrectly ignored.

### Changed

- Upgraded all Python runtimes in remediation SSM documents from Python 3.8 to Python 3.11.

### Security

- Upgraded micromatch package to mitigate [CVE-2024-4067](https://avd.aquasec.com/nvd/2024/cve-2024-4067/)

## [2.1.2] - 2024-06-20

### Fixed

- Disabled AppRegistry for certain playbooks to avoid errors when updating solution
- Created list of playbooks instead of creating stacks dynamically to avoid this in the future

### Security

- Updated braces package version for [CVE-2024-4068](https://avd.aquasec.com/nvd/cve-2024-4068)

## [2.1.1] - 2024-04-10

### Changed

- Changed order of CloudFormation parameters to emphasize the Security Control playbook
- Changed default for all playbooks other than SC to 'no'
- Updated descriptions of playbook parameters
- Updated architecture diagram

## [2.1.0] - 2024-03-28

### Added

- CloudWatch Dashboard for monitoring solution metrics
- Remediations will be scheduled in the future to prevent throttling if many remediations are triggered in a short period of time
- New support for NIST 800-53 standard
- New remediations for CloudFront.1, CloudFront.12, Codebuild.5, EC2.4, EC2.8, EC2.18, EC2.19, EC2.23, ECR.1, GuardDuty.1 IAM.3, S3.9, S3.11, S3.13, SecretsManager.1, SecretsManager.3, SecretsManager.4, SSM.4
- Support for customizable input parameters to remediations

### Changed

- Updated AFBSP to FBSP in docs
- Add HttpEndpoint parameter as enabled for EC2.8 remediation
- Updated imports for moto 5.0.0

### Fixed

- Disabled AppRegistry functionality in China regions. AppRegistry is not available in those regions
- Added missing EventBridge rules for CloudFormation.1, EC2.15, SNS.1, SNS.2, and SQS.1
- Fixed SC_SNS.2 Not executing due to wrong automation document
- Fixed RDS.4 remediation failing to remediate due to incorrect regex
- RDS.4 regex now includes snapshots created by Backup
- Enable CloudTrail encryption remediation is now a regional remediation
- Fixed SC_SQS.2 incorrect parameter
- Fixed SC_EC2.6 message on finding note
- Added AddTagsToResource to EncryptRDSSnapshot remediation role
- SNS.2 now works in regions other than where the roles are deployed
- Updated SNS.1 parameter to TopicArn instead of SNSTopicArn
- SC_RDS.1 regex now includes snapshots
- Fixed certain remediations failing in opt-in regions due to STS token endpoint
- Rules for CIS 1.4.0 no longer match on CIS 1.2.0 generator ID
- Fixed S3.6 creating malformed policy when all principals are "*"

### Security

- Upgraded urllib3

## [2.0.2] - 2023-10-24

### Security

- Upgraded @babel/traverse to mitigate CVE-2023-45133
- Upgraded urllib3 to mitigate CVE-2023-45803
- Upgraded aws-cdk-lib to mitigate CVE-2023-35165
- Upgraded @cdklabs/cdk-ssm-documents to mitigate CVE-2023-26115

## [2.0.1] - 2023-04-20

### Fixed

- Set bucket ownership property explicitly when creating logging buckets with ACLs

## [2.0.0] - 2023-03-23

### Added

- New remediations contributed by 6Pillars: CIS v1.2.0 1.20
- New AWS FSBP remediations for CloudFormation.1, EC2.15, SNS.1, SNS.2, SQS.1
- Service Catalog AppRegistry integration
- New support for Security Controls, finding deduplication
- New support for CIS v1.4.0 standard

### Changed

- Added protections to avoid deployment failure due to SSM document throttling

## [1.5.1] - 2022-12-22

### Changed

- Changed SSM document name prefixes from SHARR to ASR to support stack update
- Upgraded Lambda Python runtimes to 3.9

### Fixed

- Reverted SSM document custom resource provider to resolve intermittent deployment errors
- Fixed bug in AWS FSBP AutoScaling.1 and PCI.AutoScaling.1 remediation regexes

## [1.5.0] - 2022-05-31

### Added

- New remediations - see Implementation Guide

### Changed

- Improved cross-region remediation using resource region from Resources[0].Id
- Added custom resource provider for SSM documents to allow in-place stack upgrades

## [1.4.2] - 2022-01-14

### Changed

- Fix to correct the generator id pattern for CIS 1.2.0 Ruleset.

## [1.4.1] - 2022-01-05

### Changed

- Bug Fix for issue [47](https://github.com/aws-solutions/automated-security-response-on-aws/issues/47)
- Bug Fix for issue [48](https://github.com/aws-solutions/automated-security-response-on-aws/issues/48)

## [1.4.0] - 2021-12-13

### Changed

- Bug fixes for AWS FSBP EC2.1, CIS 3.x
- Separated Member roles from the remediations so that roles can be deployed once per account
- Roles are now global
- Cross-region remediation is now supported
- Deployment using stacksets is documented in the IG and supported by the templates
- Member account roles for remediation runbooks are now retained when the stack is deleted so that remediations that use
  these roles continue to function if the solution is removed

### Added

- Added a get_approval_requirement lambda that customers can use to implement custom business logic
- Added the ability for customers to route findings to an alterate runbook when the finding meets criteria. For example,
  potentially destructive remediations can be sent to a runbook that sends the finding data to Incident Manager.
- New remediation for AWS FSBP & PCI S3.5

## [1.3.2] - 2021-11-09

- Corrected CIS 3.1 filter pattern
- Corrected SNS Access Policy for SO0111-SHARR-LocalAlarmNotification
- Corrected KMS CMK Access Policy used by the SNS topic to allow CloudWatch use
- EvaluationPeriods for CIS 3.x alarms changed from 240 (20 hours) to 12 (1 hour)

## [1.3.1] - 2021-09-10

### Changed

- CreateLogMetricFilterAndAlarm.py changed to make Actions active, add SNS notification to
  SO0111-SHARR-LocalAlarmNotification
- Change CIS 2.8 remediation to match new finding data format

## [1.3.0] - 2021-08-30

### Added

- New AWS Foundational Best Practices (FSBP) support: EC2.6, IAM.7-8, S3.1-3
- New CIS v1.2.0 support: 2.1, 2.7, 3.1-14
- New PCI-DSS v3.2.1 Playbook support for 17 controls (see IG for details)
- Library of remediation SSM Automation runbooks
- NEWPLAYBOOK as a template for custom playbook creation

### Changed

- Updated to CDK v1.117.0
- Reduced duplicate code
- Updated CIS playbook to Orchestrator architecture
- Single Orchestrator deployment to enable multi-standard remediation with a single click
- Custom Actions now consolidated to one: "Remediate with SHARR"

### Removed

- AWS Service Catalog for Playbook deployment

## [1.2.1] - 2021-05-14

### Changed

- Corrected SSM permissions that were preventing execution of AWS-owned SSM remediation documents

## [1.2.0] - 2021-03-22

### Added

- New FSBP playbook with 12 new remediations
- New Lambda Layer for use by solution lambdas
- New Playbook architecture: Step Function, microservice Lambdas, Systems Manager runbooks
- Corrected anonymous metrics to log only on final state (FAILED or RESOLVED)
- Added logging to put anonymous metrics in solution logs as an audit trail
- Corrected the anonymous metrics UUID to use standard 8-4-4-4-12 format
- Encrypted CloudWatch logs for FSBP state machine

### Changed

- Consolidated CDK to a single installation
- Moved common/core CDK modules to source/lib
- Update CDK to 1.80.0

## [1.1.0] - 2020-11-15

### Changed

- Added support for AWS partitions other than 'aws' (aws-us-gov, aws-cn)
- Updated CDK support to 1.68.0

## [1.0.1] - 2020-09-18

### Changed

- Added info-level messages indicating action (CREATE/UPDATE) from the CreateCustomAction lambda
- Added more stringent matching on Workflow Status and Compliance Status to CloudWatch Event Rules for Custom Actions
  and CloudWatch finding events (automatic trigger)
- Added logging of the finding id to the lambda log for each remediation
- Added region name to all IAM roles
- Added region name to IAM Groups - permissions can now be granted per region
- Removed statically-defined policy names for IAM Groups
- Removed snapshot test from CDK unit tests

## [1.0.0] - 2020-08-12

### Added

- New add-on solution for AWS Security Hub with CIS v1.2.0 remediations
