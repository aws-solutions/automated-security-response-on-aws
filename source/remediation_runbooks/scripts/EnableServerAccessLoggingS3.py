import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


BOTO_CONFIG = Config(
    retries = {
            'mode': 'standard',
            'max_attempts': 10
        }
    )

def connect_to_s3():
    return boto3.client('s3', config=BOTO_CONFIG)

def create_bucket(bucket_name: str, aws_region: str) -> str:
    try:
        kwargs = {
            "Bucket": bucket_name,
        }
        if aws_region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": aws_region}

        connect_to_s3().create_bucket(**kwargs)
        return "success"
    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        # bucket already exists - return
        if exception_type == "BucketAlreadyOwnedByYou":
            print("Bucket " + bucket_name + " already exists and is owned by you")
            return "bucket_exists"
        else:
            print(ex)
            exit("Error creating bucket " + bucket_name)
    except Exception as e:
        print(e)
        exit("Error creating bucket " + bucket_name)

def create_logging_bucket(aws_account, aws_region, target_bucket_name):
    bucket_name = target_bucket_name + "-" + aws_region + "-" + aws_account

    if create_bucket(bucket_name, aws_region) == "bucket_exists":
        return bucket_name
    
    return bucket_name
        
def enable_server_access_logging(event, _):
    def __get_bucket_from_event(event):
        bucket = event.get('bucket') or exit('Bucket not specified')
        return bucket
    
    def __get_target_bucket_from_event(event):
        target_bucket = event.get('targetbucket') or exit('Target Bucket not specified')
        return target_bucket
    
    try:
        aws_account: str = event.get["account"]
        aws_region: str = event.get["region"]
        # Extract the bucket name from the event
        bucket_name = __get_bucket_from_event(event)
        target_bucket_name = create_logging_bucket(
            aws_account,
            aws_region,
            __get_target_bucket_from_event(event)
        )
        
        # Enable server access logging for the bucket
        connect_to_s3().put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': target_bucket_name,
                    'TargetPrefix': bucket_name + '/logs/'
                }
            }
        )

        return {
            "output": {
                "Message": f'S3 bucket server access logging enabled for {bucket_name}'
            }
        }

    except Exception as e:
        return {
            "output": {
                "Message": f'S3 bucket server access logging failed for {bucket_name}'
                "Error": str(e)
            }
        }
