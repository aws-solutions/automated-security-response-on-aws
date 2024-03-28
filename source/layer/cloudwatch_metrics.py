# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from typing import TYPE_CHECKING, Any, cast

import boto3
from layer.logger import Logger

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient
else:
    CloudWatchClient = object

from layer import awsapi_cached_client

if TYPE_CHECKING:
    from mypy_boto3_ssm.client import SSMClient
else:
    SSMClient = object

# initialise loggers
LOG_LEVEL = os.getenv("log_level", "info")
LOGGER = Logger(loglevel=LOG_LEVEL)


class CloudWatchMetrics:
    namespace = "ASR"

    def __init__(self):
        try:
            self.session = boto3.session.Session()
            self.region = self.session.region_name
            self.ssm_client = self.init_ssm_client()
            self.metrics_enabled = self.send_cloudwatch_metrics_enabled()
            if not self.metrics_enabled:
                return

            self.cloudwatch_client = self.init_cloudwatch_client()

        except Exception as e:
            print(e)
            LOGGER.error("Could not initialize metrics")
            raise

    def send_cloudwatch_metrics_enabled(self):
        is_enabled = False  # default value
        try:
            ssm_parm = "/Solutions/SO0111/sendCloudwatchMetrics"
            send_cloudwatch_metrics_from_ssm = (
                self.ssm_client.get_parameter(Name=ssm_parm)  # type: ignore[union-attr]
                .get("Parameter")
                .get("Value")
            )

            if (
                send_cloudwatch_metrics_from_ssm is None
                or send_cloudwatch_metrics_from_ssm.lower() not in ["yes", "no"]
            ):
                print(
                    f'Unexpected value for {ssm_parm}: {send_cloudwatch_metrics_from_ssm}. Defaulting to "no"'
                )
            elif send_cloudwatch_metrics_from_ssm.lower() == "yes":
                is_enabled = True

        except Exception as e:
            print(e)

        return is_enabled

    def init_ssm_client(self) -> SSMClient:
        try:
            new_ssm_client = awsapi_cached_client.AWSCachedClient(
                self.region
            ).get_connection("ssm")
            return cast(SSMClient, new_ssm_client)

        except Exception as e:
            print(f"Could not connect to ssm: {str(e)}")
            raise e

    def init_cloudwatch_client(self) -> CloudWatchClient:
        try:
            new_cloudwatch_client = awsapi_cached_client.AWSCachedClient(
                self.region
            ).get_connection("cloudwatch")
            return cast(CloudWatchClient, new_cloudwatch_client)
        except Exception as e:
            print(f"Could not connect to cloudwatch: {str(e)}")
            raise e

    def send_metric(self, metric: Any) -> None:
        try:
            if metric is None or not self.metrics_enabled or not self.cloudwatch_client:
                return
            self.cloudwatch_client.put_metric_data(
                MetricData=[metric],
                Namespace=self.namespace,
            )
        except Exception as exception:
            print(f"Could not send cloudwatch metric: {str(exception)}")
