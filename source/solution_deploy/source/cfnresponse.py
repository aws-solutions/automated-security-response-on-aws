# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Send custom resource status to CloudFormation"""

import json
import re
from typing import TYPE_CHECKING, Any

import urllib3

if TYPE_CHECKING:
    from aws_lambda_powertools.utilities.data_classes import (
        CloudFormationCustomResourceEvent,
    )
    from aws_lambda_powertools.utilities.typing import LambdaContext
else:
    CloudFormationCustomResourceEvent = object
    LambdaContext = object

SUCCESS = "SUCCESS"
FAILED = "FAILED"

http = urllib3.PoolManager()


def redact_presigned_url(message: str) -> str:
    """Redact the query string of any presigned URL found in a string.

    A failed PUT to the CloudFormation callback URL can surface the presigned
    ResponseURL inside the exception text. Presigned URLs are prohibited data
    in logs, and their query string carries every sensitive value (credential,
    signature, and the session token X-Amz-Security-Token when the URL is signed
    with role credentials). The whole query string is stripped rather than
    masking individual parameters, so nothing sensitive leaks even if AWS adds
    new signing parameters.

    The match anchors on the "?" alone, so it covers both full URLs and the bare
    path a urllib3 MaxRetryError renders ("Max retries exceeded with url:
    /key?X-Amz-Signature=..."), and it runs in linear time on any input.
    Matching stops at whitespace or a closing paren so the trailing
    "(Caused by ...)" context is preserved.
    """
    return re.sub(r"\?[^\s)]*", "?*****", message)


def send(
    event: CloudFormationCustomResourceEvent,
    context: LambdaContext,
    response_status: str,
    response_data: dict[str, Any],
    physical_resource_id: str | None = None,
    no_echo: bool = False,
    reason: str | None = None,
) -> None:
    """Send custom resource status to CloudFormation"""
    response_url = event["ResponseURL"]

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
        print(
            "send(..) failed executing http.request(..):",
            redact_presigned_url(str(ex)),
        )
