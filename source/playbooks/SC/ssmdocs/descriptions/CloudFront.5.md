### Document name - AWSConfigRemediation-EnableCloudFrontAccessLogs

## What does this document do?
This runbook enables access logging on an Amazon CloudFront (CloudFront) distribution you specify using the [UpdateDistribution](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_UpdateDistribution.html) API.

## Input Parameters
* AutomationAssumeRole: (Required) The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that allows Systems Manager Automation to perform the actions on your behalf.
* CloudFrontId: (Required) The ID of the CloudFront distribution you want to enable access logging on.
* BucketName: (Required) The name of the Amazon Simple Storage Service (Amazon S3) bucket you want to store access logs in. Buckets in the af-south-1, ap-east-1, eu-south-1, and me-south-1 AWS Region are not supported.
* Prefix: (Optional) An optional string that you want CloudFront to prefix to the access log filenames for your distribution, for example, myprefix/.
* IncludeCookies: (Required) Set this parameter to 'true', if you want cookies to be included in the access logs.

## Output Parameters
* UpdateDistributionAndVerify.Response: The standard HTTP response from the UpdateDistribution API.