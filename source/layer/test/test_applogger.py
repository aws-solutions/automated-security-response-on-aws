# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Simple test to validate that the request format coming from the Cfn template
will turn into a valid API call.
"""
import os
from datetime import date

import boto3
from botocore.stub import ANY, Stubber
from layer.applogger import LogHandler

my_session = boto3.session.Session()
my_region = my_session.region_name


# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def test_init_default():
    applogger = LogHandler("mystream")
    assert applogger.log_group == "SO0111-SHARR"


# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
def test_create_logstream(mocker):
    applogger = LogHandler("mystream")
    assert applogger.log_group == "SO0111-SHARR"

    logsclient = boto3.client("logs")
    stubbed_logs_client = Stubber(logsclient)
    stubbed_logs_client.add_response(
        "create_log_stream",
        {},
        {
            "logGroupName": "SO0111-SHARR",
            "logStreamName": "MYSTREAM-" + str(date.today()),
        },
    )
    # stubbed_logs_client.add_response(
    #     'put_log_events',
    #     {},
    # )
    stubbed_logs_client.add_response(
        "put_log_events",
        {
            "nextSequenceToken": "string",
            "rejectedLogEventsInfo": {
                "tooNewLogEventStartIndex": 123,
                "tooOldLogEventEndIndex": 123,
                "expiredLogEventEndIndex": 123,
            },
        },
        {
            "logGroupName": "SO0111-SHARR",
            "logStreamName": "MYSTREAM-" + str(date.today()),
            "logEvents": ANY,
            "sequenceToken": "0",
        },
    )
    stubbed_logs_client.activate()

    mocker.patch("layer.applogger.get_logs_connection", return_value=logsclient)

    applogger.add_message("A door is ajar")
    assert len(applogger._buffer) == 1
    assert applogger._buffer_size == 40
    applogger.flush()


# #------------------------------------------------------------------------------
# #
# #------------------------------------------------------------------------------
def test_init_custom():
    os.environ["SOLUTION_LOGGROUP"] = "MY-LOG-GROUP"
    applogger = LogHandler("mystream")
    assert applogger.log_group == "MY-LOG-GROUP"
    # put back the original value
    del os.environ["SOLUTION_LOGGROUP"]
