import boto3

def verify_drop_invalid_headers(event, context):
    elbv2_client = boto3.client("elbv2")
    load_balancer_arn = event["LoadBalancerArn"]
    response = elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=load_balancer_arn)
    for attribute in response["Attributes"]:
        if (attribute["Key"] == "routing.http.drop_invalid_header_fields.enabled" and attribute["Value"] == "true"):
            return {
                "Output": {
                    "message": "AWS APPLICATION LOAD BALANCER TO DROP INVALID HEADERS SETTING IS SUCCESSFUL.",
                    "HTTPResponse": response
                }
            }
    raise Exception("VERIFICATION FAILED, AWS APPLICATION LOAD BALANCER {} TO DROP INVALID HEADERS SETTING IS NOT SUCCESSFUL.".format(load_balancer_arn))