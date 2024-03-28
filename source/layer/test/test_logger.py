# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from layer.logger import Logger


def test_logger_init_debug():
    logger_test = Logger(loglevel="debug")
    assert logger_test.log.getEffectiveLevel() == 10


def test_logger_init_info():
    logger_test = Logger(loglevel="info")
    assert logger_test.log.getEffectiveLevel() == 20


def test_logger_init_warning():
    logger_test = Logger(loglevel="warning")
    assert logger_test.log.getEffectiveLevel() == 30


# TODO
# 1. Add a test for DateTimeEncoder
# 2. Add a test for _format
