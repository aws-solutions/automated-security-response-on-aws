import boto3
def is_cloudfront_origin_access_identity_associated(cloudfront_client,cloudfront_distribution):
    response = cloudfront_client.get_distribution_config(Id=cloudfront_distribution)
    for counter in range(response["DistributionConfig"]["Origins"]["Quantity"]):
        if ("S3OriginConfig" in response["DistributionConfig"]["Origins"]["Items"][counter] and response["DistributionConfig"]["Origins"]["Items"][counter]["S3OriginConfig"]["OriginAccessIdentity"] == ""):
            error = f"VERIFICATION FAILED. ORIGIN ACCESS IDENTITY FOR AMAZON CLOUDFRONT DISTRIBUTION {cloudfront_distribution} IS NOT SET."
            raise Exception(error)
    return "Verification of 'EnableCloudFrontOriginAccessIdentity' is successful."

def handler(event, context):
    cloudfront_client = boto3.client("cloudfront")
    origin_access_identity = "origin-access-identity/cloudfront/" + event["origin_access_identity"]
    response = cloudfront_client.get_distribution_config(Id=event["cloudfront_distribution"])
    s3_origin = False
    for counter in range(response["DistributionConfig"]["Origins"]["Quantity"]):
        if ("S3OriginConfig" in response["DistributionConfig"]["Origins"]["Items"][counter]):
            s3_origin = True
            if (response["DistributionConfig"]["Origins"]["Items"][counter]["S3OriginConfig"]["OriginAccessIdentity"] == ""):
                response["DistributionConfig"]["Origins"]["Items"][counter]["S3OriginConfig"]["OriginAccessIdentity"] = origin_access_identity
    if (s3_origin == False):
        error = f"ORIGIN ACCESS IDENTITY FOR AMAZON CLOUDFRONT DISTRIBUTION {event['cloudfront_distribution']} WITH NO S3 ORIGIN TYPE CAN NOT BE SET."
        raise Exception(error)
    update_response = cloudfront_client.update_distribution(
        DistributionConfig=response["DistributionConfig"],
        Id=event["cloudfront_distribution"],
        IfMatch=response["ETag"]
    )
    output = is_cloudfront_origin_access_identity_associated(cloudfront_client,event["cloudfront_distribution"])
    return { 
        "Output": {
            "Message": output,
            "HTTPResponse":  update_response["ResponseMetadata"] 
        }
    }