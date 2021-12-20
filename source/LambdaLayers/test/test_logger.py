#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import pytest
from pytest_mock import mocker
from logger import Logger

def test_logger_init_debug():
    logger_test = Logger(loglevel='debug')
    assert logger_test.log.getEffectiveLevel() == 10

def test_logger_init_info():
    logger_test = Logger(loglevel='info')
    assert logger_test.log.getEffectiveLevel() == 20

def test_logger_init_warning():
    logger_test = Logger(loglevel='warning')
    assert logger_test.log.getEffectiveLevel() == 30

# TODO 
# 1. Add a test for DateTimeEncoder
# 2. Add a test for _format