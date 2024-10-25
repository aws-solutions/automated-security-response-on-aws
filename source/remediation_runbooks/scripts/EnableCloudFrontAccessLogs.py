import boto3

def get_distribution_configuration(cloudfront_client, distribution_id):
    waiter = cloudfront_client.get_waiter('distribution_deployed')
    waiter.wait(Id=distribution_id)
    get_response = cloudfront_client.get_distribution_config(Id=distribution_id)
    return get_response

def update_distribution_configuration(cloudfront_client, distribution_id, distribution_content, logging_content):
    distribution_content['DistributionConfig']['Logging'] = logging_content
    etag = distribution_content['ETag']
    updated_configuration = distribution_content['DistributionConfig']
    update_distribution_response = cloudfront_client.update_distribution(
        DistributionConfig=updated_configuration,
        Id=distribution_id,
        IfMatch=etag
    )
    return update_distribution_response

def get_bucket_region(bucket_name):
    s3_client = boto3.client("s3")
    bucket_response = s3_client.get_bucket_location(Bucket=bucket_name)
    bucket_region = bucket_response["LocationConstraint"]
    if bucket_region is None:
        bucket_region = "us-east-1"
    return bucket_region

def handler(event, context):
    cloudfront_client = boto3.client("cloudfront")
    distribution_id = event["DistributionId"]
    bucket_name = event["BucketName"]
    bucket_region = get_bucket_region(bucket_name)

    if bucket_region in ["af-south-1", "ap-east-1", "eu-south-1", "me-south-1"]:
        raise Exception("CloudFront doesn't deliver access logs to buckets which resides in these region: {}".format(bucket_region))

    logging_content = {
        "Enabled": True,
        "Bucket": ".".join([bucket_name, "s3", bucket_region, "amazonaws", "com"]),
        "Prefix": event["Prefix"],
        "IncludeCookies": event["IncludeCookies"]
    }
    get_distribution_response = get_distribution_configuration(cloudfront_client, distribution_id)
    update_distribution = update_distribution_configuration(cloudfront_client, distribution_id, get_distribution_response, logging_content)

    # Verification of logging enabled on given Amazon Cloudfront distribution
    verify_response = get_distribution_configuration(cloudfront_client, distribution_id)
    if verify_response['DistributionConfig']['Logging'] == logging_content:
        return {
            "Message": "Verification of EnableCloudFrontAccessLogs is successful.",
            "HTTPResponse": update_distribution['ResponseMetadata']
        }
    raise Exception("VERIFICATION OF EnableCloudFrontAccessLogs FAILED.")