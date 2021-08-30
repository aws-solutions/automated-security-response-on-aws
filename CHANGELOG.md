# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
