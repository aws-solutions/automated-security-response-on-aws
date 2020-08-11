#!/usr/bin/python
###############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
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
import json
from botocore.stub import Stubber
import pytest
import lib.sechub_findings as findings
from lib.logger import Logger
from lib.applogger import LogHandler
from lib.awsapi_helpers import AWSClient
from pytest_mock import mocker

log_level = 'info'
logger = Logger(loglevel=log_level)
test_data = 'tests/test_json_data/'
stubber = Stubber(findings.securityhub)

#------------------------------------------------------------------------------
# Parse imported events
#------------------------------------------------------------------------------
def test_parse_imported():

    test_cis_13 = open(test_data + 'CIS-1.3.json')
    event = json.loads(test_cis_13.read())
    test_cis_13.close()

    finding = findings.Finding(event['detail']['findings'][0])
    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.generator_id == 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3'
    assert finding.account_id == '111111111111'
    assert finding.is_cis_ruleset() == { 
        'ruleset': 'cis-aws-foundations-benchmark', 
        'version': '1.2.0', 
        'ruleid': '1.3' 
    }
    assert finding.is_aws_fsbp_ruleset() == False

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_parse_bad_imported():
    test_file = open(test_data + 'CIS-bad.json')
    event = json.loads(test_file.read())
    test_file.close()

    with pytest.raises(findings.InvalidFindingJson):
        finding = findings.Finding(event['detail']['findings'][0])

#------------------------------------------------------------------------------
# 
#------------------------------------------------------------------------------
def test_parse_custom_mismatch():
    test_file = open(test_data + 'custom-action-mismatch.json')
    event = json.loads(test_file.read())
    test_file.close()

    finding = findings.Finding(event['detail']['findings'][0])

    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.account_id == '111111111111'
    assert not finding.is_cis_ruleset()
    assert finding.is_aws_fsbp_ruleset() == { 'ruleset': 'aws-foundational-security-best-practices', 'version': '1.0.0', 'ruleid': 'CloudTrail.1' }

#------------------------------------------------------------------------------
# Parse custom action events
#------------------------------------------------------------------------------
def test_parse_custom_match():
    test_file = open(test_data + 'CIS_1-6.json')
    event = json.loads(test_file.read())
    test_file.close()

    finding = findings.Finding(event['detail']['findings'][0])

    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.account_id == '111111111111'
    assert finding.is_cis_ruleset() == {
        'ruleset': 'cis-aws-foundations-benchmark',
        'version': '1.2.0',
        'ruleid': '1.6'
    }
    assert not finding.is_aws_fsbp_ruleset()

#------------------------------------------------------------------------------
# notify
# Criteria: absense of errors
#------------------------------------------------------------------------------
def test_notify(mocker):
    test_file = open(test_data + 'CIS_1-6.json')
    event = json.loads(test_file.read())
    test_file.close()

    finding = findings.Finding(event['detail']['findings'][0])

    logger = Logger(loglevel='info')
    logger_obj = mocker.patch('lib.logger.Logger.info', return_value=None)

    applogger = LogHandler('pytest')
    mocker.patch('lib.applogger.LogHandler.add_message', return_value='')

    # mocker.patch('lib.sechub_findings.Finding.resolve', return_value='')

    mocker.patch('lib.sechub_findings.Finding.update_text', return_value='')

    AWS = AWSClient()
    mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value='')

    test_message = {
        'Note': '',
        'State': 'INFO',
        'Account': '111111111111',
        'Remediation': 'Remediate all the things',
        'AffectedObject': 'An AWS Thingy',
        'metrics_data': {'status': 'RESOLVED'}
    }
    findings.notify(finding, test_message, logger, cwlogs=applogger, sechub=True, sns=AWS)
    logger_obj.assert_called_once_with(
        'INFO: "Remediate all the things" , Account Id: 111111111111, Resource: An AWS Thingy'
    )

    # assert logger_mock('message', mocker.ANY)
    test_message = {
    }
    findings.notify(finding, test_message, logger, cwlogs=applogger, sechub=True, sns=AWS)
    logger_obj.assert_called_with(
        'INFO: error - missing note, Account Id: error, Resource: error'
    )
