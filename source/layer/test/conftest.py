# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from unittest.mock import patch

import pytest
from layer.awsapi_cached_client import AWSCachedClient


@pytest.fixture(scope="module", autouse=True)
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["SOLUTION_ID"] = "SOTestID"
    os.environ["AWS_ACCOUNT"] = "123456789012"


@pytest.fixture(scope="module", autouse=True)
def mock_get_local_account_id():
    mock = patch.object(
        AWSCachedClient, "_get_local_account_id", return_value="111111111111"
    )
    mock.start()
    yield
    mock.stop()
