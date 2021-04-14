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
Playbook Unit Test: CIS1314.py
Run from /deployment/build/playbooks/CIS after running build-s3-dist.sh
"""
import os
os.environ['sendAnonymousMetrics'] = 'Yes'
import json
import boto3
from botocore.stub import Stubber
import pytest
from pytest_mock import mocker
import cis1314
from lib.logger import Logger
from lib.applogger import LogHandler
from lib.awsapi_helpers import BotoSession
from lib.applogger import LogHandler
import lib.sechub_findings
import tests.file_utilities as utils

log_level = 'info'
logger = Logger(loglevel=log_level)
test_data = 'tests/test_data/'

my_session = boto3.session.Session()
my_region = my_session.region_name

mock_ssm_get_parameter_uuid = {
    "Parameter": {
        "Name": "/Solutions/SO0111/anonymous_metrics_uuid",
        "Type": "String",
        "Value": "12345678-1234-1234-1234-123412341234",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": "arn:aws:ssm:us-east-1:1111111111111111:parameter/Solutions/SO0111/anonymous_metrics_uuid",
        "DataType": "text"
    }
}
mock_ssm_get_parameter_version = {
    "Parameter": {
        "Name": "/Solutions/SO0111/solution_version",
        "Type": "String",
        "Value": "v1.2.0TEST",
        "Version": 1,
        "LastModifiedDate": "2021-02-25T12:58:50.591000-05:00",
        "ARN": "arn:aws:ssm:us-east-1:1111111111111111:parameter/Solutions/SO0111/anonymous_metrics_uuid",
        "DataType": "text"
    }
}

def test_event_good(mocker):
    # Read test data
    event = utils.load_test_data(test_data + 'cis_1-3-iamuser1.json', my_region)

    sns_message = {
        'Note': 'Access key over 90 days old found: AKIAGHJGJFGHJFGETHFG',
        'State': 'INFO',
        'Account': '111111111111',
        'Remediation': 'Deactivate unused keys over 90 days old',
        'metrics_data': mocker.ANY,
        'AffectedObject': 'Access Key: AKIAGHJGJFGHJFGETHFG'
    }

    iam_keys = {
        "AccessKeyMetadata": [
            {
                "UserName": "iamuser1",
                "AccessKeyId": "AKIAADFHWEREFGFHSDDF",
                "Status": "Active",
                "CreateDate": "2015-05-22T14:43:16+00:00"
            },
            {
                "UserName": "iamuser1",
                "AccessKeyId": "AKIAGHJGJFGHJFGETHFG",
                "Status": "Active",
                "CreateDate": "2020-05-15T15:20:04+00:00"
            }
        ]
    }

    post_metrics_expected_parms = {
        'Solution': 'SO0111',
        'UUID': '12345678-1234-1234-1234-123412341234',
        'TimeStamp': mocker.ANY,
        'Data': {
            'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3',
            'type': '1.3 Ensure credentials unused for 90 days or greater are disabled',
            'productArn': mocker.ANY,
            'finding_triggered_by': 'Security Hub Findings - Custom Action',
            'region': mocker.ANY,
            'status': 'RESOLVED'
        },
        'Version': 'v1.2.0TEST'
    }

    ssmc = boto3.client('ssm', region_name=my_region)
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )

    ssmc_s.activate()
    mocker.patch('lib.metrics.Metrics.connect_to_ssm', return_value=ssmc)

    # Mock the constructor. We don't need the session created
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    post_metrics = mocker.patch('lib.metrics.Metrics.post_metrics_to_api', return_value=None)
    mocker.patch('lib.awsapi_helpers.AWSClient.connect', return_value=None)

    # sess = BotoSession()
    iamc = boto3.client('iam', region_name=my_region)
    iamr = boto3.resource('iam', region_name=my_region)


    iamc_s = Stubber(iamc)
    iamr_s = Stubber(iamr.meta.client)

    iamc_s.add_response(
        'list_access_keys',
        iam_keys
    )
    iamr_s.add_response(
        'update_access_key',
        {}
    )
    iam_keys['AccessKeyMetadata'][0]['Status'] = 'Inactive'
    iamc_s.add_response(
        'list_access_keys',
        iam_keys
    )

    iamr_s.add_response(
        'update_access_key',
        {}
    )

    iam_keys['AccessKeyMetadata'][0]['Status'] = 'Inactive'
    iamc_s.add_response(
        'list_access_keys',
        iam_keys
    )

    iamc_s.activate()
    iamr_s.activate()

    # Replace BotoSession client/resource with our stub
    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=iamc)
    mocker.patch('lib.awsapi_helpers.BotoSession.resource', return_value=iamr)
    sns = mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock Notifier
    resolve = mocker.patch('lib.sechub_findings.Finding.resolve')
    flag = mocker.patch('lib.sechub_findings.Finding.flag')

    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    cis1314.lambda_handler(event, None)

    flag.assert_called_once_with(
        'INITIAL: "Deactivate unused keys over 90 days old" remediation started'
    )
    resolve.assert_called_once_with(
        'RESOLVED: Remediation completed successfully, create new access keys using IAM console.'
    )
    sns.assert_called_with('SO0111-SHARR_Topic', sns_message, my_region)

    post_metrics.assert_called_with(post_metrics_expected_parms)

def test_event_bad(mocker):
    # Read test data
    event = utils.load_test_data(test_data + 'cis_1-3.json', my_region)

    iam_keys = {
        "AccessKeyMetadata": [
            {
                "UserName": "iamuser1",
                "AccessKeyId": "AKIAADFHWEREFGFHSDDF",
                "Status": "Active",
                "CreateDate": "2015-05-22T14:43:16+00:00"
            },
            {
                "UserName": "iamuser1",
                "AccessKeyId": "AKIAGHJGJFGHJFGETHFG",
                "Status": "Active",
                "CreateDate": "2020-05-15T15:20:04+00:00"
            }
        ]
    }

    post_metrics_expected_parms = {
        'Solution': 'SO0111',
        'UUID': '12345678-1234-1234-1234-123412341234',
        'TimeStamp': mocker.ANY,
        'Data': {
            'generator_id': 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3',
            'type': '1.3 Ensure credentials unused for 90 days or greater are disabled',
            'productArn': mocker.ANY,
            'finding_triggered_by': 'Security Hub Findings - Custom Action',
            'region': mocker.ANY,
            'status': 'FAILED'
        },
        'Version': 'v1.2.0TEST'
    }

    ssmc = boto3.client('ssm', region_name=my_region)
    ssmc_s = Stubber(ssmc)
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_uuid
    )
    ssmc_s.add_response(
        'get_parameter',
        mock_ssm_get_parameter_version
    )

    ssmc_s.activate()
    mocker.patch('lib.metrics.Metrics.connect_to_ssm', return_value=ssmc)

    # Mock the constructor. We don't need the session created
    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)
    post_metrics = mocker.patch('lib.metrics.Metrics.post_metrics_to_api', return_value=None)

    mocker.patch('lib.awsapi_helpers.BotoSession.__init__', return_value=None)

    # create client and resource directly through boto3
    iamc = boto3.client('iam', region_name=my_region)
    iamr = boto3.resource('iam', region_name=my_region)

    # stub the client
    iamc_s = Stubber(iamc)
    iamr_s = Stubber(iamr.meta.client)

    iamc_s.add_response(
        'list_access_keys',
        iam_keys
    )
    iamc_s.add_response(
        'update_access_key',
        {}
    )
    iam_keys['AccessKeyMetadata'][0]['Status'] = 'Inactive'
    iamc_s.add_response(
        'list_access_keys',
        iam_keys
    )
    iamc_s.add_response(
        'update_access_key',
        {}
    )
    # iam_keys['AccessKeyMetadata'][0]['Status'] = 'Inactive'
    iamc_s.add_response(
        'list_access_keys',
        iam_keys
    )

    iamc_s.activate()
    iamr_s.activate()

    # Mock the client and resource to return the clients we created
    mocker.patch('lib.awsapi_helpers.BotoSession.client', return_value=iamc)
    mocker.patch('lib.awsapi_helpers.BotoSession.resource', return_value=iamr)
    mocker.patch('lib.awsapi_helpers.AWSClient.postit', return_value=None)

    # Mock flush so we don't
    mocker.patch('lib.applogger.LogHandler.flush', return_value=None)

    # Mock Notifier
    init = mocker.patch('lib.sechub_findings.Finding.flag')
    update = mocker.patch('lib.sechub_findings.Finding.update_text')

    cis1314.lambda_handler(event, None)
    init.assert_called_with(
        'INITIAL: "Deactivate unused keys over 90 days old" remediation started'
    )
    update.assert_called_once_with(
        'FAILED: "Deactivate unused keys over 90 days old" remediation failed. Please remediate manually', status='FAILED'
    )
    post_metrics.assert_called_with(post_metrics_expected_parms)
