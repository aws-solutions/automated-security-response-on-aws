# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Send custom resource status to CloudFormation"""

import json

import urllib3

SUCCESS = "SUCCESS"
FAILED = "FAILED"

http = urllib3.PoolManager()


def send(
    event,
    context,
    response_status,
    response_data,
    physical_resource_id=None,
    no_echo=False,
    reason=None,
):
    """Send custom resource status to CloudFormation"""
    response_url = event["ResponseURL"]

    print(response_url)

    max_reason_length = 3854  # response can't exceed 4 kiB
    if reason and len(reason) > max_reason_length:
        reason = reason[:max_reason_length]

    response_body = {
        "Status": response_status,
        "Reason": reason
        or f"See the details in CloudWatch Log Stream: {context.log_stream_name}",
        "PhysicalResourceId": physical_resource_id or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": no_echo,
        "Data": response_data,
    }

    json_response_body = json.dumps(response_body)

    print("Response body:")
    print(json_response_body)

    headers = {"content-type": "", "content-length": str(len(json_response_body))}

    try:
        response = http.request(
            "PUT", response_url, headers=headers, body=json_response_body
        )
        print("Status code:", response.status)

    except Exception as ex:
        print("send(..) failed executing http.request(..):", ex)
