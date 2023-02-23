# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2023-01-17

### Added
- New remediations contributed by 6Pillars: AFSBP IAM.1/CIS v1.2.0 1.22/PCI.IAM.3, CIS v1.2.0 1.16, CIS v1.2.0 1.20

### Changed
- Added support for Security Controls, finding deduplication

## [1.5.1] - 2022-12-22

### Changed

- Changed SSM document name prefixes from SHARR to ASR to support stack update
- Upgraded Lambda Python runtimes to 3.9

### Fixed

- Reverted SSM document custom resource provider to resolve intermittent deployment errors
- Fixed bug in AFSBP AutoScaling.1 and PCI.AutoScaling.1 remediation regexes

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
- Bug Fix for issue [47](https://github.com/aws-solutions/aws-security-hub-automated-response-and-remediation/issues/47)
- Bug Fix for issue [48](https://github.com/aws-solutions/aws-security-hub-automated-response-and-remediation/issues/48)


## [1.4.0] - 2021-12-13

### Changed
- Bug fixes for AFSBP EC2.1, CIS 3.x
- Separated Member roles from the remediations so that roles can be deployed once per account
- Roles are now global
- Cross-region remediation is now supported
- Deployment using stacksets is documented in the IG and supported by the templates
- Member account roles for remediation runbooks are now retained when the stack is deleted so that remediations that use these roles continue to function if the solution is removed

### Added
- Added a get_approval_requirement lambda that customers can use to implement custom business logic
- Added the ability for customers to route findings to an alterate runbook when the finding meets criteria. For example, potentially destructive remediations can be sent to a runbook that sends the finding data to Incident Manager.
- New remediation for AFSBP & PCI S3.5

## [1.3.2] - 2021-11-09
- Corrected CIS 3.1 filter pattern
- Corrected SNS Access Policy for SO0111-SHARR-LocalAlarmNotification
- Corrected KMS CMK Access Policy used by the SNS topic to allow CloudWatch use
- EvaluationPeriods for CIS 3.x alarms changed from 240 (20 hours) to 12 (1 hour)

## [1.3.1] - 2021-09-10

### Changed
- CreateLogMetricFilterAndAlarm.py changed to make Actions active, add SNS notification to SO0111-SHARR-LocalAlarmNotification
- Change CIS 2.8 remediation to match new finding data format

## [1.3.0] - 2021-08-30

### Added
- New AWS Foundational Best Practices (AFSBP) support: EC2.6, IAM.7-8, S3.1-3
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
- New AFSBP playbook with 12 new remediations
- New Lambda Layer for use by solution lambdas
- New Playbook architecture: Step Function, microservice Lambdas, Systems Manager runbooks
- Corrected anonymous metrics to log only on final state (FAILED or RESOLVED)
- Added logging to put anonymous metrics in solution logs as an audit trail
- Corrected the anonymous metrics UUID to use standard 8-4-4-4-12 format
- Encrypted CloudWatch logs for AFSBP state machine

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
- Added more stringent matching on Workflow Status and Compliance Status to CloudWatch Event Rules for Custom Actions and CloudWatch finding events (automatic trigger)
- Added logging of the finding id to the lambda log for each remediation
- Added region name to all IAM roles
- Added region name to IAM Groups - permissions can now be granted per region
- Removed statically-defined policy names for IAM Groups
- Removed snapshot test from CDK unit tests

## [1.0.0] - 2020-08-12
### Added
- New add-on solution for AWS Security Hub with CIS v1.2.0 remediations
