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

"""
Simple test to validate that the request format coming from the Cfn template
will turn into a valid API call.
"""
import json
import boto3
from botocore.stub import Stubber
import pytest
from pytest_mock import mocker
import sechub_findings as findings
from logger import Logger
from applogger import LogHandler
import utils

log_level = 'info'
logger = Logger(loglevel=log_level)
test_data = 'test/test_json_data/'
stubber = Stubber(findings.securityhub)

my_session = boto3.session.Session()
my_region = my_session.region_name

ssmclient = boto3.client('ssm')
stubbed_ssm_client = Stubber(ssmclient)

#------------------------------------------------------------------------------
# CIS v1.2.0
#------------------------------------------------------------------------------
def test_parse_cis_v120(mocker):

    test_data_in = open(test_data + 'CIS-1.3.json')
    event = json.loads(test_data_in.read())
    test_data_in.close()

    stubbed_ssm_client.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f'arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/shortname',
                "DataType": "text"
            }
        })
    stubbed_ssm_client.add_client_error(
        'get_parameter','ParameterNotFound','The requested parameter does not exist'
    )
    stubbed_ssm_client.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/1.2.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f'arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/version',
                "DataType": "text"
            }
        })
    stubbed_ssm_client.activate()

    mocker.patch('sechub_findings.get_ssm_connection', return_value=ssmclient)

    finding = findings.Finding(event['detail']['findings'][0])
    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.generator_id == 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3'
    assert finding.account_id == '111111111111'
    assert finding.standard_name == 'cis-aws-foundations-benchmark'
    assert finding.standard_shortname == 'CIS'
    assert finding.standard_version == '1.2.0'
    assert finding.standard_control == '1.3'
    assert finding.standard_version_supported == 'True'

    stubbed_ssm_client.deactivate()

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
# CIS v1.7.0 finding should show unsupported
#------------------------------------------------------------------------------
def test_parse_unsupported_version(mocker):
    test_data_in = open(test_data + 'CIS_unsupversion.json')
    event = json.loads(test_data_in.read())
    test_data_in.close()

    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/cis-aws-foundations-benchmark/shortname",
                "Type": "String",
                "Value": "CIS",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f'arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/cis-aws-foundations-benchmark/shortname',
                "DataType": "text"
            }
        })

    stubbed_ssm_client.add_client_error(
        'get_parameter','ParameterNotFound','The requested parameter does not exist'
    )
    stubbed_ssm_client.activate()

    mocker.patch('sechub_findings.get_ssm_connection', return_value=ssmclient)
    
    finding = findings.Finding(event['detail']['findings'][0])

    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.generator_id == 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.7.0/rule/1.6'
    assert finding.account_id == '111111111111'
    assert finding.standard_name == 'cis-aws-foundations-benchmark'
    assert finding.standard_shortname == 'CIS'
    assert finding.standard_version == '1.7.0'
    assert finding.standard_control == '1.6'
    assert finding.standard_version_supported == 'False'

    stubbed_ssm_client.deactivate()

#------------------------------------------------------------------------------
# AFSBP v1.0.0
#------------------------------------------------------------------------------
def test_parse_afsbp_v100(mocker):

    test_data_in = open(test_data + 'afsbp-ec2.7.json')
    event = json.loads(test_data_in.read())
    test_data_in.close()

    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/shortname",
                "Type": "String",
                "Value": "AFSBP",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:11:30.658000-04:00",
                "ARN": f'arn:aws:ssm:{my_region}:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/shortname',
                "DataType": "text"
            }
        })
    stubbed_ssm_client.add_client_error(
        'get_parameter','ParameterNotFound','The requested parameter does not exist'
    )
    stubbed_ssm_client.add_response(
        'get_parameter',
        {
            "Parameter": {
                "Name": "/Solutions/SO0111/aws-foundational-security-best-practices/1.0.0",
                "Type": "String",
                "Value": "enabled",
                "Version": 1,
                "LastModifiedDate": "2021-04-23T08:12:13.893000-04:00",
                "ARN": f'arn:aws:ssm:us-{my_region}-1:111111111111:parameter/Solutions/SO0111/aws-foundational-security-best-practices/version',
                "DataType": "text"
            }
        })
    stubbed_ssm_client.activate()

    mocker.patch('sechub_findings.get_ssm_connection', return_value=ssmclient)

    finding = findings.Finding(event['detail']['findings'][0])
    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.account_id == '111111111111'
    assert finding.standard_name == 'aws-foundational-security-best-practices'
    assert finding.standard_shortname == 'AFSBP'
    assert finding.standard_version == '1.0.0'
    assert finding.standard_control == 'EC2.7'
    assert finding.standard_version_supported == 'True'

    stubbed_ssm_client.deactivate()

#------------------------------------------------------------------------------
# Security Standard not found
#------------------------------------------------------------------------------
def test_undefined_security_standard(mocker):

    test_data_in = open(test_data + 'afsbp-ec2.7.json')
    event = json.loads(test_data_in.read())
    test_data_in.close()

    event['detail']['findings'][0]['ProductFields']['StandardsControlArn'] = \
        "arn:aws:securityhub:::standards/aws-invalid-security-standard/v/1.2.3/ABC.1"

    stubbed_ssm_client = Stubber(ssmclient)

    stubbed_ssm_client.add_client_error(
        'get_parameter','ParameterNotFound','The requested parameter does not exist'
    )

    stubbed_ssm_client.add_client_error(
        'get_parameter','ParameterNotFound','The requested parameter does not exist'
    )

    stubbed_ssm_client.add_client_error(
        'get_parameter','ParameterNotFound','The requested parameter does not exist'
    )
 
    stubbed_ssm_client.activate()

    mocker.patch('sechub_findings.get_ssm_connection', return_value=ssmclient)

    finding = findings.Finding(event['detail']['findings'][0])
    assert finding.details.get('Id') == event['detail']['findings'][0]['Id']
    assert finding.account_id == '111111111111'
    assert finding.standard_name == 'aws-invalid-security-standard'
    assert finding.standard_shortname == 'error'
    assert finding.security_standard == 'notfound'
    assert finding.standard_version == '1.2.3'
    assert finding.standard_control == 'ABC.1'
    assert finding.standard_version_supported == 'False'

    stubbed_ssm_client.deactivate()

# def test_simple_notification(mocker):
#     mocker.patch('utils.publish_to_sns', return_value='11111111')
#     notification = findings.SHARRNotification(
#         'AFSBP',
#         my_region,
#         's3.5'
#     )
#     notification.severity = 'INFO'
#     notification.send_to_sns = True
#     notification.finding_info = {
#         'finding_id': 'aaaaaaaa-bbbb-cccc-dddd-123456789012',
#         'finding_description': 'finding description',
#         'standard_name': 'standard long name',
#         'standard_version': 'v1.0.0',
#         'standard_control': 's3.5',
#         'title': 'A door should not be ajar',
#         'region': 'us-west-2',
#         'account': '111122223333',
#         'finding_arn': "arn:aws:securityhub:us-east-1:111122223333:subscription/pci-dss/v/3.2.1/PCI.S3.1/finding/3f74c9bf-bbb3-40d8-8781-796096b35571",
#     }
    
#     assert notification.notify() == '11111111'
#     utils.publish_to_sns.assert_called_once_with('foo')
