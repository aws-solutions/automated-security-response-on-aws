### Document Name - ASR-AFSBP_1.0.0_CodeBuild.2

## What does this document do?
This document removes CodeBuild project environment variables containing clear text credentials and replaces them with Amazon EC2 Systems Manager Parameters.

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* Remediation.Output

## Documentation Links
* [AWS FSBP v1.0.0 CodeBuild.2](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-codebuild-2)
