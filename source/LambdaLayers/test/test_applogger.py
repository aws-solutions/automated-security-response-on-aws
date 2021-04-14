#!/usr/bin/python
###############################################################################
#  Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

"""
Simple test to validate that the request format coming from the Cfn template
will turn into a valid API call.
"""
import os
from datetime import date
from botocore.stub import Stubber, ANY
import pytest
from applogger import LogHandler

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_init_default():

    applogger = LogHandler('mystream')
    assert applogger.log_group == 'SO0111-SHARR'
    
#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_create_logstream():

    applogger = LogHandler('mystream')
    stubber = Stubber(applogger._log_client)
    stubber.add_response(
        'create_log_stream',
        {},
        {
            'logGroupName': 'SO0111-SHARR',
            'logStreamName': 'MYSTREAM-' + str(date.today())
        }
    )
    stubber.activate()
    assert applogger.log_group == 'SO0111-SHARR'
    applogger.add_message('A door is ajar')

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_add_message():

    applogger = LogHandler('mystream')
    stubber = Stubber(applogger._log_client)
    stubber.add_response(
        'create_log_stream',
        {},
    )
    stubber.add_response(
        'put_log_events',
        {
            'nextSequenceToken': 'string',
            'rejectedLogEventsInfo': {
                'tooNewLogEventStartIndex': 123,
                'tooOldLogEventEndIndex': 123,
                'expiredLogEventEndIndex': 123
            }
        },
        {
            'logGroupName': 'SO0111-SHARR',
            'logStreamName': 'MYSTREAM-' + str(date.today()),
            'logEvents': ANY,
            'sequenceToken': '0'
        }
    )
    stubber.activate()
    assert applogger.log_group == 'SO0111-SHARR'
    applogger.add_message('A door is ajar')
    assert len(applogger._buffer) == 1
    assert applogger._buffer_size == 40
    applogger.flush()

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_init_custom():

    os.environ['SOLUTION_LOGGROUP'] = 'MY-LOG-GROUP'
    applogger = LogHandler('mystream')
    assert applogger.log_group == 'MY-LOG-GROUP'
    # put back the original value
    del os.environ['SOLUTION_LOGGROUP']

