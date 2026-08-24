### Document Name - ASR-IAMAccessAnalyzer.ExternalAccess

## What does this document do?

This document remediates IAM Access Analyzer external access findings by tightening resource policies.
It replaces wildcard principals (`Principal: "*"`) with the owning account ID and adds an
`aws:PrincipalOrgID` condition key if the account is a member of an AWS Organization.

## Input Parameters

- Finding: (Required) Security Hub finding details JSON
- AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters

- Remediation.Output

## Documentation Links

- [IAM Access Analyzer Findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html)
