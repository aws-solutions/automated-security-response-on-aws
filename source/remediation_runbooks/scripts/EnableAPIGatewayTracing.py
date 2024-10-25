import boto3
import botocore
import re

def lambda_handler(event, _):
    config_client = boto3.client("config")
    apigateway_client = boto3.client("apigateway")
    stage_id = event["StageArn"]
    rest_api_id = ""

    stage_response = config_client.get_resource_config_history(resourceType="AWS::ApiGateway::Stage", resourceId=stage_id, limit=1)
    stage_name = stage_response["configurationItems"][0]["resourceName"]
    rest_api_arn = stage_response["configurationItems"][0]["relationships"][0]["resourceId"]
    rest_api_arn_pattern = "^arn:.*:/restapis/(.*)"
    rest_api_match = re.match(rest_api_arn_pattern, rest_api_arn)
    if not rest_api_match:
        raise Exception("GIVEN AMAZON API GATEWAY STAGE ID IS NOT ASSOCIATED WITH ANY REST API ID.")
    rest_api_id = rest_api_match.groups()[0]

    # Enables tracing to the given Amazon API Gateway stage.
    update_stage_response = apigateway_client.update_stage(stageName=stage_name, restApiId=rest_api_id, patchOperations=[
        {
            "op": "replace",
            "path": "/tracingEnabled",
            "value": "true"
        },
    ])

    # Verifies that the stage tracing has enabled.
    get_stage_response = apigateway_client.get_stage(restApiId=rest_api_id, stageName=stage_name)
    if get_stage_response['tracingEnabled']:
        return {
            "output": {
                "message": "Verification of 'Enable Tracing' is successful.",
                "HTTPResponse": update_stage_response["ResponseMetadata"]
            }
        }
    error_message = f"VERIFICATION FAILED. API GATEWAY STAGE {stage_name} TRACING NOT ENABLED."
    raise Exception(error_message)