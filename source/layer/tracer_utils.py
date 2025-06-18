# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os

from aws_lambda_powertools import Tracer

SERVICE_NAME = os.getenv("SOLUTION_TMN")


def init_tracer():
    tracer = Tracer(service=SERVICE_NAME)
    return tracer
