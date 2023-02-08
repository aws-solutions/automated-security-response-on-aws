# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
def process_results(event, _):
    print(f'Created encrypted SNS topic {event["sns_topic_arn"]}')
    print(f'Created encrypted Config bucket {event["config_bucket"]}')
    print(f'Created access logging for Config bucket in bucket {event["logging_bucket"]}')
    print('Enabled AWS Config by creating a default recorder')
    return {
        "response": {
            "message": "AWS Config successfully enabled",
            "status": "Success"
        }
    }
