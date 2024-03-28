### Document Name - ASR-AFSBP_1.0.0_RDS.2
## What does this document do?
This document disables public access to RDS instances by calling another SSM document

## Input Parameters
* Finding: (Required) Security Hub finding details JSON
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Documentation Links
* [AWS FSBP RDS.2](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-rds-2)

## Troubleshooting
* ModifyDBInstance isn't supported for a DB instance in a Multi-AZ DB Cluster.
 - This remediation will not work on an instance within a MySQL or PostgreSQL Multi-AZ Cluster due to limitations with the RDS API. 
