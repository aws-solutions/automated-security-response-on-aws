# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
def process_results(event, _):
    print(f'Created encrypted CloudTrail bucket {event["cloudtrail_bucket"]}')
    print(
        f'Created access logging for CloudTrail bucket in bucket {event["logging_bucket"]}'
    )
    print("Enabled multi-region AWS CloudTrail")
    return {
        "response": {
            "message": "AWS CloudTrail successfully enabled",
            "status": "Success",
        }
    }
