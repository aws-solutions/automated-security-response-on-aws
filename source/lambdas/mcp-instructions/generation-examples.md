# ASR Runbook Examples

These examples demonstrate common SSM Automation remediation and verification
patterns. The same examples are bundled with the deployed ASR MCP authoring
guidance, and repository tests keep the two copies synchronized.

The description title in each example is the hand-authored form, `ASR-{ControlId}`.
A runbook released through the managed `deploy_runbook` service titles itself
`ASR-Custom-{ControlId}` instead; the title is cosmetic, and `validation-rules.md`'s
`naming-convention` states both forms. Everything below the title is the same on
either path.

Each example shows a complete runbook. The `description` field uses the multi-line format described in Rules (h3 title, then h2 sub-sections for What/Input/Output/Standards). Reproduce this heading structure in your output.

**Adapt direct resource parameters for manual Custom Runbooks.** The examples
use `BucketName`, `TopicArn`, `RDSClusterARN`, or `LogGroupName` to keep each step
pattern focused. A manual Custom Runbook must instead declare `Finding`, derive
the identifier from it, and give every additional parameter a default.

**Example 1: Simple API call + verification (SNS encryption)**

User request: "Enable encryption on an SNS topic using a KMS key"
Pattern: `aws:executeAwsApi` remediation then `aws:assertAwsResourceProperty` verification

<RUNBOOK>
```yaml
schemaVersion: "0.3"
description: |
  ### Document name - ASR-SNS.1
  ## What does this document do?
  This document enables encryption on a given Amazon SNS topic using the SetTopicAttributes API.
  ## Input Parameters
  * AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  * TopicArn: (Required) The ARN of the Amazon SNS Topic.
  * KmsKeyArn: (Required) The ARN of the AWS KMS Key.
  ## Output Parameters
  * EncryptSNSTopic.Response - The standard HTTP response from the SetTopicAttributes API call.
  ## Security Standards / Controls
  * AWS FSBP v1.0.0: SNS.1
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  AutomationAssumeRole:
    type: String
    description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'
  KmsKeyArn:
    type: String
    default: >-
      {{ssm:/Solutions/SO0111/CMK_REMEDIATION_ARN}}
    description: The ARN of the KMS key created by ASR for this remediation.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):kms:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:(?:alias/[a-zA-Z0-9:/_-]+|key/(?i:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}))$'
  TopicArn:
    type: String
    description: (Required) The ARN of the Amazon SNS Topic.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):sns:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:([a-zA-Z0-9_-]{1,80}(?:\.fifo)?)$'
outputs:
  - EncryptSNSTopic.Response
mainSteps:
  - name: EncryptSNSTopic
    action: "aws:executeAwsApi"
    description: |
      Makes SetTopicAttributes API call to enable encryption.
    timeoutSeconds: 600
    isEnd: false
    inputs:
      Service: sns
      Api: SetTopicAttributes
      TopicArn: "{{TopicArn}}"
      AttributeName: KmsMasterKeyId
      AttributeValue: "{{KmsKeyArn}}"
    outputs:
      - Name: Response
        Selector: $
        Type: StringMap
  - name: VerifyTopicEncryption
    action: aws:assertAwsResourceProperty
    description: |
      Verifies the given Amazon SNS Topic is encrypted with the AWS KMS Key ARN.
    timeoutSeconds: 600
    isEnd: true
    inputs:
      Service: sns
      Api: GetTopicAttributes
      TopicArn: "{{TopicArn}}"
      PropertySelector: Attributes.KmsMasterKeyId
      DesiredValues:
        - "{{ KmsKeyArn }}"
```
</RUNBOOK>

Key points: KmsKeyArn defaults to ASR's SSM-managed CMK. Verification uses `aws:assertAwsResourceProperty` to confirm the attribute was set.

One deliberate difference from the shipped runbooks: their `KmsKeyArn` pattern
writes the alias branch as `(?:^(alias/)[a-zA-Z0-9:/_-]+$)`, and that inner `^`
can never match — by then the engine has consumed `arn:…:kms:…:` from position
0, so the branch is dead and only `key/<uuid>` is accepted. The pattern above
drops the inner anchors. Copy it, not the shipped one; if you are editing a
shipped runbook rather than writing a new one, leave its pattern alone: widening
what a deployed runbook accepts is a compatibility change, and it belongs in its
own validated change rather than alongside an unrelated edit.

**Example 2: Pre-check + remediation + verification (RDS deletion protection)**

User request: "Enable deletion protection on an RDS cluster"
Pattern: Describe then Assert available then Modify then Assert changed

<RUNBOOK>
```yaml
schemaVersion: "0.3"
description: |
  ### Document name - ASR-RDS.7
  ## What does this document do?
  This document enables Deletion Protection on a given Amazon RDS cluster using the ModifyDBCluster API.
  ## Input Parameters
  * AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  * RDSClusterARN: (Required) ARN of the Amazon RDS cluster.
  ## Output Parameters
  * EnableRDSClusterDeletionProtection.ModifyDBClusterResponse: The standard HTTP response from the ModifyDBCluster API.
  ## Security Standards / Controls
  * AWS FSBP v1.0.0: RDS.7
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  AutomationAssumeRole:
    type: String
    description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'
  RDSClusterARN:
    type: String
    description: (Required) Amazon RDS cluster ARN.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:cluster:.+$'
outputs:
  - EnableRDSClusterDeletionProtection.ModifyDBClusterResponse
mainSteps:
  - name: DescribeDBClusters
    action: aws:executeAwsApi
    description: |
      Gets the DBClusterIdentifier from the cluster ARN.
    timeoutSeconds: 600
    isEnd: false
    inputs:
      Service: rds
      Api: DescribeDBClusters
      DBClusterIdentifier: "{{ RDSClusterARN }}"
    outputs:
      - Name: DbClusterIdentifier
        Selector: $.DBClusters[0].DBClusterIdentifier
        Type: String
  - name: VerifyClusterAvailable
    action: aws:assertAwsResourceProperty
    description: |
      Verifies the RDS cluster status is available before modifying.
    timeoutSeconds: 600
    isEnd: false
    inputs:
      Service: rds
      Api: DescribeDBClusters
      DBClusterIdentifier: "{{ RDSClusterARN }}"
      PropertySelector: $.DBClusters[0].Status
      DesiredValues:
        - "available"
  - name: EnableRDSClusterDeletionProtection
    action: "aws:executeAwsApi"
    description: |
      Enables deletion protection on the Amazon RDS Cluster.
    timeoutSeconds: 600
    isEnd: false
    inputs:
      Service: rds
      Api: ModifyDBCluster
      DBClusterIdentifier: "{{ DescribeDBClusters.DbClusterIdentifier }}"
      DeletionProtection: true
    outputs:
      - Name: ModifyDBClusterResponse
        Selector: $
        Type: StringMap
  - name: VerifyDeletionProtection
    action: "aws:assertAwsResourceProperty"
    description: |
      Verifies that deletion protection has been enabled.
    timeoutSeconds: 600
    isEnd: true
    inputs:
      Service: rds
      Api: DescribeDBClusters
      DBClusterIdentifier: "{{ DescribeDBClusters.DbClusterIdentifier }}"
      PropertySelector: "$.DBClusters[0].DeletionProtection"
      DesiredValues:
        - "True"
```
</RUNBOOK>

Key points: Step 1 extracts the identifier. Step 2 pre-checks the cluster is available. Step 3 modifies. Step 4 verifies. Steps reference prior outputs via `{{ StepName.OutputName }}`.

**Example 3: Script-based remediation (S3 public access block)**

User request: "Block all public access on an S3 bucket"
Pattern: `aws:executeScript` for remediation then `aws:executeScript` for verification (when multiple properties must be checked)

<RUNBOOK>
```yaml
schemaVersion: "0.3"
description: |
  ### Document name - ASR-S3.2
  ## What does this document do?
  This document configures the PublicAccessBlock settings for an Amazon S3 bucket to block all public access.
  ## Input Parameters
  * AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  * BucketName: (Required) Name of the S3 bucket (not the ARN).
  ## Output Parameters
  * ConfigureS3BucketPublicAccessBlock.Output - Response from the remediation script.
  ## Security Standards / Controls
  * AWS FSBP v1.0.0: S3.2
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  BucketName:
    type: String
    description: (Required) The bucket name (not the ARN).
    allowedPattern: '(?=^.{3,63}$)(?!^(\d+\.)+\d+$)(^(([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])$)'
  AutomationAssumeRole:
    type: String
    description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'
outputs:
  - ConfigureS3BucketPublicAccessBlock.Output
mainSteps:
  - name: ConfigureS3BucketPublicAccessBlock
    action: "aws:executeScript"
    description: |
      Configures the S3 bucket PublicAccessBlock to block all public access.
    timeoutSeconds: 600
    isCritical: true
    isEnd: false
    inputs:
      Runtime: python3.11
      Handler: handle_s3_bucket
      InputPayload:
        Bucket: "{{BucketName}}"
      Script: |-
        import boto3

        def handle_s3_bucket(event, context):
            s3 = boto3.client('s3')
            bucket = event['Bucket']
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True,
                },
            )
            response = s3.get_public_access_block(Bucket=bucket)
            config = response['PublicAccessBlockConfiguration']
            return {
                'Bucket': bucket,
                'BlockPublicAcls': config['BlockPublicAcls'],
                'IgnorePublicAcls': config['IgnorePublicAcls'],
                'BlockPublicPolicy': config['BlockPublicPolicy'],
                'RestrictPublicBuckets': config['RestrictPublicBuckets'],
            }
    outputs:
      - Name: Output
        Selector: $.Payload
        Type: StringMap
  - name: VerifyPublicAccessBlock
    action: "aws:executeScript"
    description: |
      Verifies all four PublicAccessBlock settings are enabled.
    timeoutSeconds: 600
    isEnd: true
    inputs:
      Runtime: python3.11
      Handler: verify
      InputPayload:
        Bucket: "{{BucketName}}"
      Script: |-
        import boto3

        def verify(event, context):
            s3 = boto3.client('s3')
            response = s3.get_public_access_block(Bucket=event['Bucket'])
            config = response['PublicAccessBlockConfiguration']
            for setting in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']:
                if not config.get(setting, False):
                    raise Exception(f'{setting} is not enabled on bucket {event["Bucket"]}')
            return {'status': 'VERIFIED', 'Bucket': event['Bucket']}
    outputs:
      - Name: Output
        Selector: $.Payload
        Type: StringMap
```
</RUNBOOK>

Key points: Use `aws:executeScript` when multiple API calls or conditional logic is needed. Verification script raises an exception on failure. `isCritical: true` on the remediation step.

**Example 4: Optional parameter with default (CloudWatch log retention)**

User request: "Set CloudWatch Log Group retention to a configurable number of days"
Pattern: `aws:executeAwsApi` then `aws:executeScript` verification (when assert can't check the property directly)

<RUNBOOK>
```yaml
schemaVersion: "0.3"
description: |
  ### Document name - ASR-CloudWatch.16
  ## What does this document do?
  This document sets the retention period on a CloudWatch Log Group.
  ## Input Parameters
  * AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
  * LogGroupName: (Required) The name of the CloudWatch Log Group.
  * RetentionDays: (Optional) The number of days to retain log events. Default: 365.
  ## Output Parameters
  * SetRetention.Response - The HTTP response from PutRetentionPolicy.
  ## Security Standards / Controls
  * NIST 800-53 Rev5: CloudWatch.16
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  AutomationAssumeRole:
    type: String
    description: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.
    allowedPattern: '^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role/[\w+=,.@-]+$'
  LogGroupName:
    type: String
    description: (Required) The name of the CloudWatch Log Group.
    allowedPattern: '^[A-Za-z0-9/\-_#.]{1,512}$'
  RetentionDays:
    type: Integer
    description: (Optional) The number of days to retain log events.
    default: 365
    allowedValues:
      - 1
      - 3
      - 5
      - 7
      - 14
      - 30
      - 60
      - 90
      - 120
      - 150
      - 180
      - 365
      - 400
      - 545
      - 731
      - 1096
      - 1827
      - 2192
      - 2557
      - 2922
      - 3288
      - 3653
outputs:
  - SetRetention.Response
mainSteps:
  - name: SetRetention
    action: "aws:executeAwsApi"
    description: |
      Sets the retention policy on the Log Group.
    timeoutSeconds: 600
    isCritical: true
    isEnd: false
    maxAttempts: 3
    inputs:
      Service: logs
      Api: PutRetentionPolicy
      logGroupName: "{{ LogGroupName }}"
      retentionInDays: "{{ RetentionDays }}"
    outputs:
      - Name: Response
        Selector: $
        Type: StringMap
  - name: VerifyRetention
    action: "aws:executeScript"
    description: |
      Verifies the retention period was set correctly.
    timeoutSeconds: 600
    isEnd: true
    inputs:
      Runtime: python3.11
      Handler: verify_retention
      InputPayload:
        LogGroupName: "{{ LogGroupName }}"
        ExpectedDays: "{{ RetentionDays }}"
      Script: |-
        import boto3

        def verify_retention(event, context):
            logs = boto3.client('logs')
            response = logs.describe_log_groups(logGroupNamePrefix=event['LogGroupName'])
            for group in response.get('logGroups', []):
                if group['logGroupName'] == event['LogGroupName']:
                    actual = group.get('retentionInDays')
                    expected = int(event['ExpectedDays'])
                    if actual != expected:
                        raise Exception(f'Retention mismatch: expected {expected}, got {actual}')
                    return {'status': 'VERIFIED', 'retentionInDays': actual}
            raise Exception(f'Log group not found: {event["LogGroupName"]}')
    outputs:
      - Name: Output
        Selector: $.Payload
        Type: StringMap
```
</RUNBOOK>

Key points: `RetentionDays` has a `default: 365` because it's a behavioral parameter. It constrains with `allowedValues` rather than an `allowedPattern`, because `PutRetentionPolicy` accepts a fixed enumeration — a regex like `^\d{1,4}$` would let `9999` through to an API rejection at run time. Use `allowedValues` whenever the API defines a closed set, and `allowedPattern` for open-ended values. `maxAttempts: 3` for eventual consistency. Verification uses a script because `describe_log_groups` returns a list that needs filtering.
