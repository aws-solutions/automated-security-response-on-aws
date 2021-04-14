# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
