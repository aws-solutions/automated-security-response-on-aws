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

# Test Event
# {
#     "RequestType": "Create",
#     "RequestId": "request_id",
#     "ResponseURL": "response_url",
#     "ResourceType": "Custom::UpdatableRunbook",
#     "LogicalResourceId": "resource_id",
#     "StackId": "stack_id",
#     "ResourceProperties": {
#         "Content": "runbook_content",
#         "Name": "runbook_name",
#         "VersionName": "version_name", # optional
#         "DocumentType": "Automation",
#         "DocumentFormat": "YAML"
#     }
# }

import boto3
import botocore
import cfnresponse
import logger
import re
import json
import os

LOG_LEVEL = os.getenv('LOG_LEVEL', 'info')
logger = logger.Logger(loglevel = LOG_LEVEL)

config_kwargs = {
    'retries': {
        'total_max_attempts': 10,
        'mode': 'adaptive'
    }
}
SOLUTION_ID = os.getenv('SOLUTION_ID', None)
if SOLUTION_ID:
    config_kwargs['user_agent_extra'] = SOLUTION_ID
BOTO_CONFIG = botocore.config.Config(**config_kwargs)

def get_ssm_client():
    return boto3.client('ssm', config = BOTO_CONFIG)

class UpdatableRunbook:
    def __init__(self, properties):
        self._properties = properties

    def _kwargs(self, required_properties, optional_properties):
        kwargs = {}
        for property in required_properties:
            if property not in self._properties:
                logger.error("Missing property '${property}'}")
                raise ValueError("Missing property '${property}'")
            kwargs[property] = self._properties.get(property)
        for property in optional_properties:
            if property in self._properties:
                kwargs[property] = self._properties.get(property)
        return kwargs

    def create(self):
        required_properties = ['Content', 'Name', 'DocumentType']
        # Though 'Requires' and 'Tags' are optional parameters for create, update does not support these fields currently
        optional_properties = ['Attachments', 'DisplayName', 'VersionName', 'DocumentFormat', 'TargetType']
        kwargs = self._kwargs(required_properties, optional_properties)
        try:
            response = get_ssm_client().create_document(**kwargs)
            logger.info(response)
            return response['DocumentDescription']['Name']
        except botocore.exceptions.ClientError as client_error:
            if client_error.response['Error']['Code'] == 'DocumentAlreadyExists':
                logger.info(client_error.response)
                logger.info('Assuming conflicting document is left by a failed deployment or rollback. Updating.')
                self.update()
                return kwargs['Name']
            else:
                raise

    def _next_available_version_name(self):
        client = get_ssm_client()
        document_version_names = []
        response = client.list_document_versions(Name = self._properties['Name'])
        for document_version in response['DocumentVersions']:
            document_version_names.append(document_version.get('VersionName', ''))
        token = response.get('NextToken', '')
        while (token):
            response = client.list_document_versions(Name = self._properties['Name'], NextToken = token)
            for document_version in response['DocumentVersions']:
                document_version_names.append(document_version.get('VersionName', ''))
            token = response.get('NextToken', '')

        version_name = self._properties.get('VersionName', '')
        prefix = f'{version_name}_' if version_name else ''
        versioning_schema = re.compile(r'^' + re.escape(prefix) + r'Rev_(\d+)$')
        newest_version = 1
        for version_str in document_version_names:
            match = versioning_schema.match(version_str)
            if match:
                version_int = int(match.group(1))
                if version_int > newest_version:
                    newest_version = version_int

        return f'{prefix}Rev_{str(newest_version + 1)}'

    def update(self):
        update_document_required_properties = ['Name', 'Content']
        update_document_optional_properties = ['Attachments', 'DisplayName', 'VersionName', 'DocumentFormat', 'TargetType']
        update_document_kwargs = self._kwargs(update_document_required_properties, update_document_optional_properties)
        # Though 'DocumentVersion' is an optional parameter for update, we control it as a provider
        update_document_kwargs['DocumentVersion'] = '$LATEST'
        client = get_ssm_client()
        try:
            response = client.update_document(**update_document_kwargs)
            logger.info(response)
            version = response['DocumentDescription']['DocumentVersion']
        except botocore.exceptions.ClientError as client_error:
            if client_error.response['Error']['Code'] == 'DuplicateDocumentContent':
                # This can happen when rolling back a failed update
                logger.info('Ignoring error updating document with duplicate content.')
                return '$LATEST'
            elif client_error.response['Error']['Code'] == 'DuplicateDocumentVersionName':
                # This can happen with dev builds with the same version name
                self._properties['VersionName'] = self._next_available_version_name()
                logger.info(f'VersionName conflict, trying again with {self._properties["VersionName"]}')
                return self.update()
            else:
                raise

        update_version_required_poperties = ['Name']
        update_version_optional_properties = []
        update_version_kwargs = self._kwargs(update_version_required_poperties, update_version_optional_properties)
        update_version_kwargs['DocumentVersion'] = version
        response = client.update_document_default_version(**update_version_kwargs)
        logger.info(response)
        updated_version = response['Description']['DefaultVersion']
        if updated_version != version:
            raise RuntimeError("Updating default version did not match updated version, expected ${version}, got ${updated_version}")
        return updated_version

    def delete(self):
        required_properties = ['Name']
        optional_properties = []
        # Though 'DocumentName' and 'VersionName' are optional parameters for delete, as provider we delete all versions
        # Though 'Force' is an optional parameter for delete, we control it as a provider
        kwargs = self._kwargs(required_properties, optional_properties)
        try:
            get_ssm_client().delete_document(**kwargs)
        except botocore.exceptions.ClientError as client_error:
            if client_error.response['Error']['Code'] == 'InvalidDocument':
                logger.info('Ignoring error deleting non-existent document.')
            else:
                raise

    def physical_resource_id(self):
        return self._properties.get('Name', '')

def lambda_handler(event, context):
    properties = event.get('ResourceProperties', {})
    logger.info(json.dumps(properties))
    response_data = {}

    try:
        status = cfnresponse.SUCCESS
        runbook = UpdatableRunbook(properties)
        requestType = event['RequestType']
        if requestType == 'Create':
            name = runbook.create()
            response_data['Name'] = name
        elif requestType == 'Update':
            version = runbook.update()
            response_data['DocumentVersion'] = version
        elif requestType == 'Delete':
            runbook.delete()
        else:
            logger.error(f'Invalid request type: {requestType}')
            status = cfnresponse.FAILED

        cfnresponse.send(event, context, status, response_data, runbook.physical_resource_id())
    except Exception as error:
        reason = f'An exception occurred:\n{error.__class__.__name__}: {str(error)}'
        logger.error(reason)
        max_reason_length = 3854 # response can't exceed 4 kiB
        truncated_reason = reason[:max_reason_length] if len(reason) > max_reason_length else reason
        cfnresponse.send(event, context, cfnresponse.FAILED, response_data, runbook.physical_resource_id(), reason = truncated_reason)
