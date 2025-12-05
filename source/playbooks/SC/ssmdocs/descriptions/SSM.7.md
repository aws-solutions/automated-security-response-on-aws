# SSM.7 - SSM documents should have the block public sharing setting enabled

## Description
This control checks whether the block public sharing setting is enabled for AWS Systems Manager documents at the account level. The control fails if the block public sharing setting is disabled.

When this setting is enabled, it prevents all SSM documents in the account from being shared publicly, providing account-wide protection against accidental public exposure.

## Remediation
The remediation enables the block public sharing setting at the account level by updating the SSM service setting `/ssm/documents/console/public-sharing-permission` to `Disable`.

### Input Parameters
- **AccountId**: The AWS Account ID where the setting will be enabled (extracted from resource ID format `AWS::::Account:<ACCOUNT_ID>`)

### Output Parameters
- **status**: Returns "SUCCESS" when the setting is successfully enabled, or "NO_CHANGE_REQUIRED" if already enabled
- **setting_value**: The final value of the setting ("Disable" means public sharing is blocked)

## Resource Format

### Old Security Hub (ASFF Schema)
```json
{
  "Resources": [{
    "Type": "AwsAccount",
    "Id": "AWS::::Account:<ACCOUNT_ID>"
  }]
}
```

### New Security Hub (OCSF Schema)
```json
{
  "resources": [{
    "type": "AwsAccount",
    "uid": "AWS::::Account:<ACCOUNT_ID>"
  }]
}
```

Both formats use the same resource ID pattern: `AWS::::Account:<ACCOUNT_ID>` where `<ACCOUNT_ID>` is a 12-digit AWS account number.

The remediation extracts the 12-digit account ID using regex: `^AWS::::Account:(\d{12})$`

## Comparison with SSM.4

| Control | SSM.4 | SSM.7 |
|---------|-------|-------|
| **Scope** | Document-level | Account-level |
| **Resource Type** | `AwsSsmDocument` | `AwsAccount` |
| **Resource ID** | Document ARN | `AWS::::Account:XXXXXXXXXXXX` |
| **Action** | Removes "all" from specific document | Enables block public sharing setting |
| **Prevention** | No (reactive) | Yes (proactive) |

## References
- [AWS Security Hub SSM.7](https://docs.aws.amazon.com/securityhub/latest/userguide/ssm-controls.html#ssm-7)
- [AWS Systems Manager Service Settings](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-service-settings.html)
- [Block Public Sharing for SSM Documents](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-before-you-share.html#block-public-sharing)
