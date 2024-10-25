### Document name - AWSConfigRemediation-EnableCloudFrontOriginAccessIdentity

## What does this document do?
This document configures the origin access identity on a given Amazon CloudFront distribution with S3 Origins type using the [UpdateDistribution](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_UpdateDistribution.html) API.
Note: This document will enable the same CloudFront Origin Access Identity for all Origins of S3 Origin Type without origin access identity for the given Amazon CloudFront Distribution. 
    This document does not automatically grant read permission to the origin access identity, so Amazon CloudFront can access objects in your Amazon S3 bucket. You need to update your Amazon S3 bucket permissions to enable access.

## Input Parameters
* CloudFrontDistributionId: (Required) The Amazon CloudFront distribution's identifier.
* OriginAccessIdentityId: (Required) The Amazon CloudFront origin access identity to associate with the origin.
* AutomationAssumeRole: (Required) The ARN of the role that allows Automation to perform the actions on your behalf.

## Output Parameters
* UpdateDistributionAndVerify.Output: The standard HTTP response from the UpdateDistribution API.