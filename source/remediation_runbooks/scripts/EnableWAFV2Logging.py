import boto3

def enable_wafv2_logging_and_verify(event, context):
    firehose_client = boto3.client('firehose')
    wafv2_client = boto3.client('wafv2')
    web_acl_arn = event["ResourceArn"]
    delivery_stream_arn = event["LogDestinationConfigs"]
    delivery_stream_name = delivery_stream_arn.split("/")[-1]

    response = firehose_client.describe_delivery_stream(DeliveryStreamName=delivery_stream_name, Limit=1)
    if response["DeliveryStreamDescription"]["DeliveryStreamARN"] != delivery_stream_arn:
        raise Exception("UPDATE FAILED, AMAZON KINESIS DATA FIREHOSE ARN PROVIDED DOESN'T EXISTS.")

    update_response = wafv2_client.put_logging_configuration(
        LoggingConfiguration={
            "ResourceArn": web_acl_arn,
            "LogDestinationConfigs": [
                delivery_stream_arn,
            ]
        }
    )
    get_response = wafv2_client.get_logging_configuration(ResourceArn=web_acl_arn)
    if get_response["LoggingConfiguration"]["LogDestinationConfigs"] == [delivery_stream_arn]:
        return {
            "output": {
                "Message": "Enable Logging configuration for AWS WAFV2 web ACL is SUCCESSFUL",
                "HTTPResponsePutAPI": update_response,
                "HTTPResponseGetAPI": get_response
                }
            }
    raise Exception("VERIFICATION FAILED, LOGGING CONFIGURATION FOR AWS WAFV2 IS NOT ENABLED.")