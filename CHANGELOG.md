# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2026-10-12

### Added

- Custom remediation support: author, register, test, and deploy your own remediation runbooks alongside the built-in controls. Custom runbooks are resolved per member account with built-in runbooks taking precedence, gated behind a test that must pass before deploy, and their coverage is surfaced to operators (unverified custom coverage is reported as a gap rather than as coverage).
- Optional MCP (Model Context Protocol) server, exposing the deployed solution's tools to AI clients (Claude Code, Kiro, OpenAI Codex CLI) through an Amazon Bedrock AgentCore Gateway. Enabled with the `EnableMcpServer` parameter, it is deployable independently of the Web UI, verifies the Cognito access token signature and pins the app client before reading any claim, tier-scopes tool grants, and emits tool metrics with an alarm on tool errors.
- AI remediation-authoring skill (`ai-assets/`): a shared skill plus host adapters for Claude Code, Kiro, and OpenAI Codex CLI that guide an AI coding agent through authoring, validating, testing, and deploying ASR remediations. It supports two workflows: Custom Runbooks deployed into an existing ASR environment, and built-in remediations contributed to the solution source.
- Snapshot-based remediation rollback: for supported controls, the solution captures a pre-remediation snapshot during remediation and lets an administrator or delegated administrator reverse a completed remediation from the Web UI. Enabled with the new `EnableRollback` parameter; rollback restores the recorded snapshot by its exact version, aborts on drift, and is one-shot per finding.

### Fixed

- Fixed the pre-processor rejecting Security Hub V2 Coverage findings with `InvalidFindingSchemaError`, which emitted a `PRE_PROCESSOR_FAILED` metric and an ERROR log on every coverage refresh. Coverage findings report whether GuardDuty, Inspector, Macie or Security Hub CSPM is enabled and have no remediation; they are now dropped at DEBUG level before schema detection, and the failure metric for any remaining unrecognized finding shape now carries the finding's `class_uid` and product ARN.
- Fixed pre-production builds (`build-s3-dist.sh -t`) stripping the `DEV-` prefix at some call sites but not others, so the findings status topic, the six member configuration parameters, and the role, instance profile, topic and bucket names referenced by CloudTrail.5, CloudTrail.7, EC2.6, RDS.6, SNS.2, SSM.1, Config.1 and CloudWatch.1 were created under one name and looked up under another.

### Changed

- Pre-production builds now use production resource names, so a `-t` build can no longer be deployed beside a production deployment in one account and Region, and upgrading an existing `-t` deployment replaces the findings status topic and drops any subscriptions created on it.
- The CloudTrail Action Log group (`/aws/lambda/SO0111-ASR-CloudTrailEvents`) is now retained on stack deletion instead of being deleted, so its ten-year audit records survive a stack delete or a failed-update rollback. After deleting the admin stack the log group remains in the account, and a later redeploy in the same account must remove it first or the deployment fails because the fixed log group name already exists.

### Security

- Fixed an issue where `ASR-ReplaceCodeBuildClearTextCredentials` (CodeBuild.2) wrote the plaintext `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` values into its automation execution history.
- Removed logging of full event objects across the Orchestrator Lambdas and the WebUI deployer, replacing them with explicit non-sensitive fields so the Security Hub finding body is no longer written to logs.
- Stopped logging the CloudFormation `ResponseURL` (a presigned S3 URL) in `cfnresponse.py`, and redacted the query string of any presigned URL that surfaces in a failed-callback error message so its credential, signature, and session token cannot leak.
- Upgraded brace-expansion to mitigate [CVE-2026-102276](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p), [CVE-2026-102277](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr) and [CVE-2026-102278](https://github.com/advisories/GHSA-qhr7-859c-m2p7). The copy bundled inside aws-cdk-lib is not yet patched upstream.
- Upgraded werkzeug to 3.1.9 to mitigate [CVE-2026-102598](https://github.com/advisories/GHSA-g6x2-hccm-hh4m) (denial of service via `safe_join()` Windows special-device paths). werkzeug is a development/test-only dependency.
- Upgraded source-map-js to 1.2.2 in the Web UI to mitigate [CVE-2026-93749](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) (denial of service via malformed indexed source maps).
- Upgraded undici to mitigate [CVE-2026-18149](https://github.com/advisories/GHSA-pmjh-fq2x-6v4x), [CVE-2026-18540](https://github.com/advisories/GHSA-r53p-7pc4-xj5r), [CVE-2026-19534](https://github.com/advisories/GHSA-rfgv-xxqx-mfg5), [CVE-2026-84890](https://github.com/advisories/GHSA-3xpg-4rpp-hhhm), [CVE-2026-84933](https://github.com/advisories/GHSA-2jfj-6hjv-fm6j), [CVE-2026-84947](https://github.com/advisories/GHSA-2gqq-gqf2-x968), [CVE-2026-84961](https://github.com/advisories/GHSA-w293-vg96-wgc3), [CVE-2026-85008](https://github.com/advisories/GHSA-8436-99hf-9mmv), [CVE-2026-85014](https://github.com/advisories/GHSA-rx4f-c7p8-82vq) and [CVE-2026-85024](https://github.com/advisories/GHSA-3wwx-pv8p-q78v).
- Upgraded urllib3 to mitigate [CVE-2026-97687](https://github.com/advisories/GHSA-8988-9cw3-xx77), [CVE-2026-97688](https://github.com/advisories/GHSA-gh4c-6fx4-qh6g) and [CVE-2026-97689](https://github.com/advisories/GHSA-vxq7-64xx-v4gw).
- Upgraded virtualenv to mitigate [CVE-2026-102925](https://github.com/advisories/GHSA-p58f-9548-mpm2), [CVE-2026-102930](https://github.com/advisories/GHSA-94p9-xgh2-xp45), [CVE-2026-102937](https://github.com/advisories/GHSA-x78j-v8h9-3j2q) and [CVE-2026-102938](https://github.com/advisories/GHSA-9h9j-4vrj-gf7g).
- Removed the `browserslist` override added in 4.0.2. Every dependency now resolves a patched browserslist on its own.

## [4.0.2] - 2026-09-15

### Fixed

- Fixed the member stack failing to deploy to more than one Region in the same account. The `ASR-RemediationConfigBucketAccess` IAM managed policy used a fixed name, and because IAM managed policies are account-global, the second Regional deployment failed with an "already exists" error. The policy is now named per Region and scoped to that Region's remediation configuration bucket. ([#323](https://github.com/aws-solutions/automated-security-response-on-aws/issues/323))
- Removed a hardcoded IAM role name in the optional CloudTrail Action Log stack so CloudFormation generates a unique name. The Action Log feature remains supported in a single Region per account.

### Changed

- When upgrading from v4.0.0 or v4.0.1, the previous `ASR-RemediationConfigBucketAccess` managed policy is retained rather than deleted, so EC2 instances already patched by the Inspector.InstanceVulnerability remediation keep the access they were granted. This policy can be removed manually once no IAM role references it.

### Security

- Set a minimum `browserslist` version of 4.28.7 to prevent a transitive dependency from reintroducing [CVE-2026-73088](https://github.com/advisories/GHSA-73wf-gq98-2v4g).

## [4.0.1] - 2026-09-10

### Security

- Upgraded browserslist to mitigate [CVE-2026-73088](https://github.com/advisories/GHSA-73wf-gq98-2v4g) and [CVE-2026-73089](https://github.com/advisories/GHSA-c83g-rgw3-j3cx).
- Upgraded @humanfs/node to mitigate [GHSA-p498-v437-472g](https://github.com/advisories/GHSA-p498-v437-472g).
- Upgraded @cdklabs/cdk-ssm-documents to mitigate [CVE-2026-45820](https://github.com/advisories/GHSA-px8p-9vwx-vf98) in the bundled fflate dependency.
- Upgraded js-yaml to mitigate [CVE-2026-84375](https://github.com/advisories/GHSA-2883-xcg3-v3hh).
- Upgraded vitest to mitigate [CVE-2026-84373](https://github.com/advisories/GHSA-82fw-gwwq-j7x9) in the @vitest/mocker dependency.

## [4.0.0] - 2026-08-26

### Added

- Multi-service remediation for high-confidence, low-risk findings from Amazon Inspector, Amazon GuardDuty, and Amazon Macie, in both Security Hub CSPM (ASFF) and Security Hub v2 (OCSF) formats. GuardDuty and Macie remediations are first-line containment and require manual follow-up.
- Automated Remediation Controls in the Web UI: manage automation for 100+ controls, with reusable resource filters (account, OU, ARN pattern, tag) applied per-control in include/exclude modes and role-based access.
- Findings Notifications: configurable delivery channels (Email, Slack, JIRA, ServiceNow, SNS) with severity filtering, batching, resource-scoped targeting, and test-send.
- Remediation deadline enforcement, with a 24-hour minimum grace period, on synced and ingested findings.
- AI Toolkit for Custom Remediations: an instruction prompt that helps AI assistants author ASR-compliant remediations.
- Machine-to-machine (M2M) authenticated access to the solution API.
- New control remediations: S3.14, S3.11, and CloudFormation.3.
- AWS WAF rate-based rules and API Gateway throttling for the solution API.
- Operational metrics for multi-service remediation and mean-time-to-remediate (MTTR).

### Changed

- Pre-Processor routes multi-service findings, validates `ProductArn`, and skips findings with no resolvable control ID.
- Findings are ordered by EventBridge event time.

### Removed

- Removed the AWS-retired Security Hub controls CloudFormation.1, CodeBuild.5, S3.4, and SNS.2 from active-remediation surfaces (marked deprecated across the AFSBP, NIST 800-53, and SC playbooks).

### Fixed

- `MaxPasswordAge` on the `ASR-SetIAMPasswordPolicy` remediation runbook defaulted to `0`, which is below the minimum the IAM `UpdateAccountPasswordPolicy` API accepts, so any direct invocation that omitted the parameter failed parameter validation. The remaining defaults were also weaker than the controls they remediate and would have applied a password policy that still failed IAM.7 and IAM.11 through IAM.17. The defaults are removed, and the accepted ranges for `MaxPasswordAge` and `PasswordReusePrevention` no longer admit `0` or an empty value.

- `Inspector.InstanceVulnerability` end-to-end patching (SSM document 64 KiB split, IAM scoping, S3 URI form, OCSF/ASFF dispatch) and remediation timeouts.
- `Macie.SensitiveDataS3Object` end-to-end delivery across the EventBridge, Pre-Processor, runbook, and finalize path.
- `GuardDuty.IAMUser` parsing of Security Hub v2 ASFF and OCSF shapes, containment for native-ARN findings, and re-contesting of manual rollbacks.
- Guard against unsupported resource types across ingest, manual remediation, and runbook execution.
- Surface skipped and missing finding IDs in remediation responses.

### Security

- Capped auto-remediation retries and stopped remediating temporary-credential (ASIA) `GuardDuty.IAMUser` findings.
- Scoped the Inspector and `GuardDuty.IAMUser` remediation roles to least privilege.
- Fail closed when a configured resource filter is missing.
- Encrypted the notification batches DynamoDB table with the solution CMK.
- Addressed insufficient API rate limiting and hardened notification/runbook input handling.
- Upgraded vitest to mitigate [CVE-2026-47429](https://github.com/advisories/GHSA-r28c-9q8g-f849).
- Upgraded vulnerable dependencies: aws-cdk-lib (bundled brace-expansion).

## [3.1.8] - 2026-07-28

### Fixed

- Resolved findings synchronization failing to complete for large Security Hub fleets by persisting per-account progress and resuming from the saved cursor.
- Granted `ssm:StartAutomationExecution` on the `document/` resource form (including the account-less `document/*` for AWS-owned runbooks such as `AWS-ConfigureS3BucketLogging`) so remediations continue to run after the SSM API change that replaced the `automation-definition/` resource form.

### Changed

- Scheduled and deployment-time findings synchronization is now orchestrated with Step Functions, including sequential account processing and bounded per-account retries.

### Security

- Upgraded vulnerable dependencies: aws-cdk-lib, js-yaml, brace-expansion, esbuild, @cdklabs/cdk-ssm-documents, @aws-sdk/client-* (3.1014.0 -> 3.1094.0), aws-amplify (6.16.4 -> 6.19.0), vite (7.3.5 -> 7.3.6), resolving transitive fast-xml-parser/@aws-sdk/xml-builder advisories
- Removed all `overrides` blocks from package.json files after confirming the CVEs they pinned are now resolved by upgrading direct dependencies to their latest versions
- Upgraded postcss to mitigate [CVE-2026-45623](https://github.com/advisories/GHSA-r28c-9q8g-f849)
- Upgraded brace-expansion to mitigate [CVE-2026-14257](https://github.com/advisories/GHSA-mh99-v99m-4gvg)
- Re-added a single `babel-plugin-istanbul` override where no parent bump resolves CVE-2026-14257, with its rationale and removal condition recorded in `overridesJustification`
- Removed the stale `fast-uri` attribution from NOTICE.txt; the package is no longer present in any dependency tree

## [3.1.7] - 2026-06-22

### Security

- Upgraded vulnerable dependencies: js-yaml, @cdklabs/cdk-ssm-documents, aws-cdk-lib, moto, react-router-dom, vite, vitest

### Removed

- Cryptography from production deployment by narrowing aws-lambda-powertools extras from ["all"] to ["tracer"]
- Unused TypeScript dependencies @middy/http-error-handler, @middy/http-urlencode-body-parser

## [3.1.6] - 2026-05-21

### Security

- Upgraded vulnerable dependencies: fast-xml-parser, urllib3, postcss, uuid, @cdklabs/cdk-ssm-documents, aws-cdk-lib, ws, idna

## [3.1.5] - 2026-04-20

### Security

- Upgraded vulnerable dependencies: aws-cdk-lib, vite, @aws-amplify (ui-react, core), aws-amplify, pytest, cryptography

## [3.1.4] - 2026-03-31

### Security

- Upgraded vulnerable dependencies: fast-xml-parser, aws-cdk-lib, @aws-sdk (clients), black (python), immutable, picomatch and handlebars

## [3.1.3] - 2026-03-03

### Security

- Upgraded vulnerable dependencies: fast-xml-parser, aws-cdk-lib, @aws-sdk (clients), jest, eslint, werkzeug, minimatch, rollup

### Fixed

- APIGateway.5 Remediation IAM Policies
- Bug causing finding status to be overwritten to "NOTIFIED" / "In Progress" in Security Hub & Security Hub CSPM

## [3.1.2] - 2026-02-16

### Security

- Upgraded vulnerable dependencies: cryptography, filelock, virtualenv, @aws-amplify, @aws-sdk (clients)

## [3.1.1] - 2026-01-13

### Fixed

- Dependency conflicts causing Web UI to hang on "Redirecting to Login...", pinned `@aws-amplify/core` in source/webui/package.json

### Security

- Upgraded vulnerable dependencies: urllib3, werkzeug, react-router-dom, @smithy/config-resolver

## [3.1.0] - 2026-01-07

### Added

- Remediation 2.1.4.2 to CIS300 playbook
- KMS Caching Optimization: S3 Bucket Keys, SQS data key reuse (60-min cache), Secrets Manager caching (5-min TTL)

### Fixed

- Add fallback for finding data parsing in send_notifications.py
- Update condition in RevokeUnauthorizedInboundRules.py to avoid removing restricted "All Traffic" rules

### Security

- Upgrade filelock dependency to 3.20.2 to mitigate [CVE-2025-68146](https://avd.aquasec.com/nvd/cve-2025-68146)

### Changed

- Update Status for Remediated Findings in Security Hub v2 by Default
- Reduced KMS API calls by 69.5% (11.98M → 3.66M) and associated costs

## [3.0.2] - 2025-12-09

### Changed

- Enable lambda code updates with stack update
- Python updated packages urllib3 (2.5.0 to 2.6.0), boto3 (1.40.39→1.40.76), botocore (1.40.39→1.40.76), AWS type stubs, cryptography (45.0.6→46.0.3), pydantic (2.11.7→2.12.5), werkzeug (3.1.3→3.1.4)
- Npm updated packages in deployment

### Added

- Batch invite users
- [SSM adaptive concurrency](https://docs.aws.amazon.com/systems-manager/latest/userguide/adaptive-concurrency.html) enabled for new accounts. Existing accounts are unaffected. Use CDK parameter `ENABLE_ADAPTIVE_CONCURRENCY` to toggle this feature
- New runbook for SSM.7
- Export CSV action to findings table

### Fixed

- New remediations are not updated in RemediationConfigurationDynamoDBTable

## [3.0.1] - 2025-11-20

### Changed

- Upgraded vulnerable dependencies `glob` and `js-yaml`
- Updated Pre-Processor failure metric to include error message and truncated record

## [3.0.0] - 2025-11-13

### Added

- Optional Web User Interface to run remediations, view past remediations, and delegate access to the solution
  - When the `ShouldDeployWebUI` parameter is *"yes"*, you must enter a value for `AdminUserEmail` which will be granted administrator access to the Web UI. You will receive temporary credential and a login link via email.
  - Deploying the Web UI provisions additional resources such as a CloudFront distribution, Cognito User Pool, S3 bucket for hosting, and more.
- Support for Security Control findings in Security Hub v2
  - The solution continues to support Security Hub CSPM in addition to Security Hub v2
- API Gateway REST API to support the new Web User Interface
- Automated remediation filtering capabilities based on Account ID, Organizational Unit ID, and resource tags
  - Controlled via SSM parameters under `ASR/Filters/`
- Pre-Processor Lambda function to centralize processing of Security Hub finding events
- DynamoDB tables to store Security Hub finding data, remediation history data, and automated remediation settings
- Complete list of supported control IDs in `solutions-reference/automated-security-response-on-aws/latest/supported-controls.json`
- EventBridge rule to run a weekly refresh of the Findings DynamoDB table
- EventBridge rule to capture and handle Step Function failures in the Orchestrator

### Changed

- Security Hub events are now consumed by a single EventBridge rule and forwarded to the Pre-processor
- Enabling / Disabling automated remediations is now controlled by the Remediation Configuration DynamoDB table, which can be modified post-deployment. See the [Implementation Guide](https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/getting-stated-with-asr.html) for details.
  - You can find the DynamoDB table name in the Stack Outputs after deploying the Admin stack
  - Automated remediations are still toggled per Control ID, and are disabled by default
- Updated several dependencies to address security vulnerabilities
- Migrated to Node's built-in randomUUID() instead of importing uuid
- This solution sends operational metrics to AWS (the "Data") about the use of this solution. We use this Data to better understand how customers use this solution and related services and products. AWS’s collection of this Data is subject to the [AWS Privacy Notice](https://aws.amazon.com/privacy/).

### Removed

- EventBridge rules per Control ID
- Filtering configuration in Admin stack parameters
  - Filtering settings are now configurable in Systems Manager Parameter Store, e.g. `ASR/Filters/AccountFilters`

### Fixed

- S3.1 control ID in the CIS v3 playbook (2.1.4 -> 2.1.4.1)
- Improved logic in EnableCloudTrailToCloudWatchLogging_waitforloggroup remediation script
- Finding link in SNS notifications now links to the finding directly, instead of the control view in the Security Hub console
- Fixed bugs in CloudTrail.5 and CloudWatch.1 remediations
- Fixed resource ID parameter in CloudTrail.4 and CloudTrail.7 control runbooks
- Improved error handling in the Orchestrator Step Function
- Included CreateServiceLinkedRole permissions in GuardDuty.1 remediation role

## [2.3.2] - 2025-08-14

### Fixed

- Fix order for ECR.1 remediation in SC list

## [2.3.1] - 2025-08-06

### Added

- AWS Lambda Powertools Logger & Tracer support for all services
- Added the SNS topic name to the logs
- Added missing ECR.1 remediation in SC list

### Fixed

- Remove tag for EventSourceMapping
- Added missing condition on log group in Admin stack to skip creation on solution re-deployment

## [2.3.0] - 2025-07-16

### Added

- Remediations for additional control ids, see `source/playbooks/SC/lib/sc_remediations.ts` for details
- Filtering by Account ID for automated remediation executions
- AssumeRoleFailure step to the Orchestrator Step Function for error handling
- Enhanced failure metric states
- Anonymized metrics for CloudFormation parameter selections
- SSM parameters security validation

### Removed

- ServiceCatalog Application Registry integration
- Deprecated `zlib` package from CloudTrail Event Processor lambda
- `requirements_dev.txt` from version control
- Redundant anonymized metric publishing from check_ssm_execution lambda

### Changed

- Upgraded NodeJS runtime for CloudTrail Event Processor lambda from 20->22
- Refactored member roles & remediation runbook stacks into separate files
- Replaced resource names and references to old solution name ("SHARR") with current solution name ("ASR")
  - Some logical IDs with references to "SHARR" were not changed to avoid breaking the update path
  - Any KMS key names/aliases/logical IDs were left unchanged to avoid disrupting encryption.
- Renamed error strings published by Orchestrator steps as "States" and consumed in cloudwatch_metrics.ts
- Removed AwsSolutionsChecks from CDK build
- Updated grouping of CloudWatch metrics parameters for clarity
- Updated dependencies: Jinja2, Cryptography, babel, aws-cdk-lib, aws-cdk, urllib3, moto, @cdklabs/cdk-ssm-documents, jest libs
- Support for Poetry v2
- Refactored lambdas and runbooks for code quality
- 'Estimated Hours Saved' dashboard widget
- Renamed CloudFormation templates to align with current solution name: Automated Security Response on AWS (ASR)
- Appended account ID to action log ManagementEvents S3 bucket to avoid bucket name clashing among member stack deployments with the same `namespace`

### Fixed

- Python handler referenced in RevokeUnusedIAMUserCredentials.yaml to match RevokeUnusedIAMUserCredentials.py
- Remediation runbooks that rely on unstable Resources.Details finding field
- Regular expression patterns used in runbooks to match KMS Key ARNs
- Race condition in applogger.py when two instances of SendNotifications lambda are running in parallel
  - Caused by lack of exception handling when log group does not yet exist

## [2.2.1] - 2025-01-27

### Changed

- Modified the org-id-lookup custom resource to avoid throwing an error when the Admin stack is deployed in a non-Organization account.

### Security

- Upgrade jinja2 to mitigate [CVE-2024-56201](https://avd.aquasec.com/nvd/cve-2024-56201)

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
