#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.         #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

from updatableRunbookProvider import lambda_handler, UpdatableRunbook, get_ssm_client
import cfnresponse
import boto3
from botocore.stub import Stubber, ANY
from botocore.exceptions import ClientError
from botocore.config import Config
import botocore.session
from pytest_mock import mocker
import pytest
from datetime import datetime
import random
import os
import copy

os.environ['AWS_REGION'] = 'us-east-1'
os.environ['AWS_PARTITION'] = 'aws'

@pytest.fixture()
def context():
    name = 'SO0111-SHARR-updatableRunbookProvider'
    version = 'v1.0.0'
    yield {
        'function_name': name,
        'function_version': version,
        'invoked_function_arn': f"arn:aws:lambda:us-east-1:123456789012:function:{name}:{version}",
        'memory_limit_in_mb': float('inf'),
        'log_group_name': 'test-group',
        'log_stream_name': 'test-stream',
        'client_context': None,
        'aws_request_id': '-'.join([''.join([random.choice('0123456789abcdef') for _ in range(0, n)]) for n in [8, 4, 4, 4, 12]])
    }

@pytest.fixture()
def mock_provider(mocker):
    mock = mocker.patch('updatableRunbookProvider.UpdatableRunbook')
    name = 'test-resource-name'
    mock.return_value.create.return_value = name
    mock.return_value.physical_resource_id.return_value = name
    mock.return_value.update.return_value = 1
    yield mock

@pytest.fixture()
def mock_provider_exception(mocker, mock_provider):
    mock_provider.return_value.create.side_effect = Exception()
    mock_provider.return_value.update.side_effect = Exception()
    mock_provider.return_value.delete.side_effect = Exception()
    yield mock_provider

@pytest.fixture()
def mock_cfnresponse(mocker):
    yield mocker.patch('cfnresponse.send')

def event_from_action(action):
    return {
        'RequestType': action,
        'RequestId': 'request_id',
        'ResponseURL': 'https://bogus',
        'ResourceType': 'Custom::UpdatableRunbook',
        'LogicalResourceId': 'resource_id',
        'StackId': 'stack_id',
        'ResourceProperties': {
            'Content': 'runbook_content',
            'Name': 'runbook_name',
            'VersionName': 'version_name',
            'DocumentType': 'Automation',
            'DocumentFormat': 'YAML'
        }
    }

@pytest.fixture()
def event_create():
    yield event_from_action('Create')

@pytest.fixture()
def event_update():
    yield event_from_action('Update')

@pytest.fixture()
def event_delete():
    yield event_from_action('Delete')

@pytest.fixture()
def event_invalid():
    yield event_from_action('Invalid')

def test_lambda_handler_create(mock_provider, mock_cfnresponse, event_create, context):
    lambda_handler(event_create, context)

    mock_provider.assert_called_once()
    mock_provider.return_value.create.assert_called_once()
    resource_id = mock_provider.return_value.physical_resource_id.return_value
    response_data = {'Name': resource_id}
    mock_cfnresponse.assert_called_once_with(event_create, context, cfnresponse.SUCCESS, response_data, resource_id)

def test_lambda_handler_update(mock_provider, mock_cfnresponse, event_update, context):
    lambda_handler(event_update, context)

    mock_provider.assert_called_once()
    mock_provider.return_value.update.assert_called_once()
    resource_id = mock_provider.return_value.physical_resource_id.return_value
    version = mock_provider.return_value.update.return_value
    response_data = {'DocumentVersion': version}
    mock_cfnresponse.assert_called_once_with(event_update, context, cfnresponse.SUCCESS, response_data, resource_id)

def test_lambda_handler_delete(mock_provider, mock_cfnresponse, event_delete, context):
    lambda_handler(event_delete, context)

    mock_provider.assert_called_once()
    mock_provider.return_value.delete.assert_called_once()
    resource_id = mock_provider.return_value.physical_resource_id.return_value
    mock_cfnresponse.assert_called_once_with(event_delete, context, cfnresponse.SUCCESS, {}, resource_id)

def test_lambda_handler_invalid(mock_provider, mock_cfnresponse, event_invalid, context):
    lambda_handler(event_invalid, context)

    mock_cfnresponse.assert_called_once_with(event_invalid, context, cfnresponse.FAILED, {}, ANY)

def test_lambda_handler_exception(mock_provider_exception, mock_cfnresponse, event_create, context):
    lambda_handler(event_create, context)

    mock_cfnresponse.assert_called_once_with(event_create, context, cfnresponse.FAILED, {}, ANY, reason = ANY)

@pytest.fixture()
def ssm_stub(mocker):
    ssm_client = boto3.client('ssm')
    mocker.patch('updatableRunbookProvider.get_ssm_client', return_value = ssm_client)
    stub = Stubber(ssm_client)
    stub.activate()
    yield stub
    stub.deactivate()

@pytest.fixture()
def resource_properties():
    yield {
        'Content': 'runbook_content',
        'Name': 'runbook_name',
        'VersionName': 'version_name',
        'DocumentType': 'Automation',
        'DocumentFormat': 'YAML',
        'DisplayName': 'display_name',
        'TargetType': '/'
    }

def response_create_update(properties, version = '1'):
    return {
        'DocumentDescription': {
            'Sha1': 'string',
            'Hash': 'string',
            'HashType': 'Sha256',
            'Name': properties['Name'],
            'DisplayName': properties.get('DisplayName', ''),
            'VersionName': properties.get('VersionName', ''),
            'Owner': 'string',
            'CreatedDate': datetime.now(),
            'Status': 'Active',
            'StatusInformation': 'string',
            'DocumentVersion': version,
            'Description': 'string',
            'Parameters': [],
            'PlatformTypes': [
                'Linux',
            ],
            'DocumentType': properties['DocumentType'],
            'SchemaVersion': 'string',
            'LatestVersion': 'string',
            'DefaultVersion': 'string',
            'DocumentFormat': properties.get('DocumentFormat', 'YAML'),
            'TargetType': properties.get('TargetType', '/'),
            'Tags': [],
            'AttachmentsInformation': [],
            'Author': 'string',
            'ApprovedVersion': 'string',
            'PendingReviewVersion': 'string',
            'ReviewStatus': 'NOT_REVIEWED',
        }
    }

def response_update_version(properties, version):
    return {
        'Description': {
            'Name': properties['Name'],
            'DefaultVersion': version,
            'DefaultVersionName': 'string'
        }
    }

@pytest.fixture()
def valid_keys_create():
    yield {'Content', 'Name', 'DocumentType', 'Attachments', 'DisplayName', 'VersionName', 'DocumentFormat', 'TargetType'}

@pytest.fixture()
def valid_keys_update():
    yield {'Content', 'Name', 'Attachments', 'DisplayName', 'VersionName', 'DocumentFormat', 'TargetType'}

@pytest.fixture()
def valid_keys_update_version():
    yield {'Name'}

@pytest.fixture()
def valid_keys_delete():
    yield {'Name'}

def strip_properties(properties, valid_keys):
    result = {}
    for key in properties:
        if key in valid_keys:
            result[key] = properties[key]
    return result

def test_provider_create(ssm_stub, resource_properties, valid_keys_create):
    ssm_stub.add_response(
        'create_document',
        response_create_update(resource_properties),
        strip_properties(resource_properties, valid_keys_create))
    provider = UpdatableRunbook(resource_properties)
    result = provider.create()
    assert result == resource_properties['Name']

def test_provider_update(ssm_stub, resource_properties, valid_keys_update, valid_keys_update_version):
    update_properties = strip_properties(resource_properties, valid_keys_update)
    update_properties['DocumentVersion'] = '$LATEST'
    updated_version = '6'
    ssm_stub.add_response(
        'update_document',
        response_create_update(resource_properties, updated_version),
        update_properties)

    update_version_properties = strip_properties(resource_properties, valid_keys_update_version)
    update_version_properties['DocumentVersion'] = updated_version
    ssm_stub.add_response(
        'update_document_default_version',
        response_update_version(resource_properties, updated_version),
        update_version_properties)

    provider = UpdatableRunbook(resource_properties)
    result = provider.update()
    assert result == updated_version

def test_provider_delete(ssm_stub, resource_properties, valid_keys_delete):
    ssm_stub.add_response('delete_document', {}, strip_properties(resource_properties, valid_keys_delete))
    provider = UpdatableRunbook(resource_properties)
    provider.delete()

def test_provider_create_already_exists(ssm_stub, resource_properties, valid_keys_update, valid_keys_update_version):
    ssm_stub.add_client_error('create_document', 'DocumentAlreadyExists')

    update_properties = strip_properties(resource_properties, valid_keys_update)
    update_properties['DocumentVersion'] = '$LATEST'
    updated_version = '2'
    ssm_stub.add_response(
        'update_document',
        response_create_update(resource_properties, updated_version),
        update_properties)

    update_version_properties = strip_properties(resource_properties, valid_keys_update_version)
    update_version_properties['DocumentVersion'] = updated_version
    ssm_stub.add_response(
        'update_document_default_version',
        response_update_version(resource_properties, updated_version),
        update_version_properties)

    provider = UpdatableRunbook(resource_properties)
    result = provider.create()
    assert result == resource_properties['Name']

def test_provider_delete_nonexistent(ssm_stub, resource_properties):
    ssm_stub.add_client_error('delete_document', 'InvalidDocument')
    provider = UpdatableRunbook(resource_properties)
    provider.delete()

def test_provider_create_exception(ssm_stub, resource_properties):
    ssm_stub.add_client_error('create_document')
    provider = UpdatableRunbook(resource_properties)
    with pytest.raises(botocore.exceptions.ClientError):
        provider.create()

def test_provider_update_exception(ssm_stub, resource_properties):
    ssm_stub.add_client_error('update_document')
    provider = UpdatableRunbook(resource_properties)
    with pytest.raises(botocore.exceptions.ClientError):
        provider.update()

def test_provider_update_version_exception(ssm_stub, resource_properties, valid_keys_update):
    update_properties = strip_properties(resource_properties, valid_keys_update)
    update_properties['DocumentVersion'] = '$LATEST'
    updated_version = '14'
    ssm_stub.add_response(
        'update_document',
        response_create_update(resource_properties, updated_version),
        update_properties)

    ssm_stub.add_client_error('update_document_default_version')

    provider = UpdatableRunbook(resource_properties)
    with pytest.raises(botocore.exceptions.ClientError):
        provider.update()

def test_provider_delete_exception(ssm_stub, resource_properties):
    ssm_stub.add_client_error('delete_document')
    provider = UpdatableRunbook(resource_properties)
    with pytest.raises(botocore.exceptions.ClientError):
        provider.delete()

def test_provider_update_duplicate_content(ssm_stub, resource_properties):
    ssm_stub.add_client_error('update_document', 'DuplicateDocumentContent')
    provider = UpdatableRunbook(resource_properties)
    result = provider.update()
    assert result == '$LATEST'

def document_version(name, version_name = None):
    response = {
        'Name': name,
        'DisplayName': 'display_name',
        'DocumentVersion': 'document_version',
        'CreatedDate': datetime.now(),
        'IsDefaultVersion': False,
        'DocumentFormat': 'YAML',
        'Status': 'Active',
        'StatusInformation': 'string',
        'ReviewStatus': 'NOT_REVIEWED'
    }

    if version_name is not None:
        response['VersionName'] = version_name

    return response

def test_provider_update_duplicate_version_name(ssm_stub, resource_properties, valid_keys_update, valid_keys_update_version):
    name = resource_properties['Name']
    version_name = 'v1.5.0beta'
    resource_properties['VersionName'] = version_name
    ssm_stub.add_client_error('update_document', 'DuplicateDocumentVersionName')
    ssm_stub.add_response(
        'list_document_versions',
        {
            'DocumentVersions': [
                document_version(name, version_name)
            ],
            'NextToken': ''
        },
        {
            'Name': name
        }
    )
    expected_resource_properties = copy.deepcopy(resource_properties)
    expected_version_name = version_name + '_Rev_2'
    expected_resource_properties['VersionName'] = expected_version_name
    update_properties = strip_properties(expected_resource_properties, valid_keys_update)
    update_properties['DocumentVersion'] = '$LATEST'
    updated_version = '2'
    ssm_stub.add_response(
        'update_document',
        response_create_update(expected_resource_properties, updated_version),
        update_properties)
    update_version_properties = strip_properties(expected_resource_properties, valid_keys_update_version)
    update_version_properties['DocumentVersion'] = updated_version
    ssm_stub.add_response(
        'update_document_default_version',
        response_update_version(resource_properties, updated_version),
        update_version_properties)

    provider = UpdatableRunbook(resource_properties)
    result = provider.update()
    assert result == updated_version

def test_provider_update_duplicate_version_name_multiple(ssm_stub, resource_properties, valid_keys_update, valid_keys_update_version):
    name = resource_properties['Name']
    version_name = r'an arbitrary _\=.:/ version name'
    resource_properties['VersionName'] = version_name
    ssm_stub.add_client_error('update_document', 'DuplicateDocumentVersionName')
    token = 'a_token_of_some_sort'
    ssm_stub.add_response(
        'list_document_versions',
        {
            'DocumentVersions': [
                document_version(name, version_name),
                document_version(name, f'prefixed_{version_name}_Rev_10'),
                document_version(name, f'{version_name}_Rev_20.suffix'),
                document_version(name),
                document_version(name, f'{version_name}_Rev_5')
            ],
            'NextToken': token
        },
        {
            'Name': name
        }
    )
    ssm_stub.add_response(
        'list_document_versions',
        {
            'DocumentVersions': [
                document_version(name, f'{version_name}_something'),
                document_version(name, f'{version_name}_Rev_3')
            ]
        },
        {
            'Name': name,
            'NextToken': token
        }
    )
    expected_resource_properties = copy.deepcopy(resource_properties)
    expected_version_name = version_name + '_Rev_6'
    expected_resource_properties['VersionName'] = expected_version_name
    update_properties = strip_properties(expected_resource_properties, valid_keys_update)
    update_properties['DocumentVersion'] = '$LATEST'
    updated_version = '7'
    ssm_stub.add_response(
        'update_document',
        response_create_update(expected_resource_properties, updated_version),
        update_properties)
    update_version_properties = strip_properties(expected_resource_properties, valid_keys_update_version)
    update_version_properties['DocumentVersion'] = updated_version
    ssm_stub.add_response(
        'update_document_default_version',
        response_update_version(resource_properties, updated_version),
        update_version_properties)

    provider = UpdatableRunbook(resource_properties)
    result = provider.update()
    assert result == updated_version
