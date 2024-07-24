import boto3
from botocore.exceptions import ClientError

elb_client = boto3.client("elbv2")

def is_deletion_protection_enabled(elb_arn):
    elb_attributes = elb_client.describe_load_balancer_attributes(LoadBalancerArn=elb_arn)["Attributes"]
    attribute_value = list(filter(lambda x:x["Key"]=="deletion_protection.enabled", elb_attributes))[0]["Value"]
    if attribute_value:
        return True
    return False

def script_handler(event, context):
    elb_arn = event.get("LoadBalancerArn")
    elb_details = elb_client.describe_load_balancers(LoadBalancerArns=[elb_arn])["LoadBalancers"][0]
    elb_name = elb_details["LoadBalancerName"]
    if elb_details["State"]["Code"] != "active":
        raise Exception(f"SPECIFIED LOAD BALANCER {elb_name} IS NOT IN ACTIVE STATE") 

    response = elb_client.modify_load_balancer_attributes(
        LoadBalancerArn=elb_arn,
        Attributes=[{"Key": "deletion_protection.enabled","Value": "true"}]
    )
    retry_count = 0
    while retry_count < 5:
        retry_count = retry_count + 1
        if is_deletion_protection_enabled(elb_arn):
        return {
            "Message": "Deletion protection enabled successfully.",
            "HTTPResponse": response
        }
    raise Exception(f"VERIFICATION FAILED. DELETION PROTECTION IS NOT ENABLED ON ELB {elb_name}.")