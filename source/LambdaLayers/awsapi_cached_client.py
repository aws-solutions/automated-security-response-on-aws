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

# *******************************************************************
# Required Modules:
# *******************************************************************
import os
import boto3
from botocore.config import Config

class AWSCachedClient:
    """
    Maintains a hash of AWS API Client connections by region and service
    """
    account = ''
    region = ''
    client = {}
    solution_id = ''
    solution_version = 'undefined'

    def __init__(self, region):
        """
        Create a Boto3 Client object. Region is used for operations such
        as retrieving account number, and as the default for get_connection.
        """
        self.solution_id = os.getenv('SOLUTION_ID', 'SO0111')
        self.solutionVersion = os.getenv('SOLUTION_VERSION', 'undefined')
        self.region = region
        self.boto_config = Config(
            user_agent_extra=f'AwsSolution/{self.solution_id}/{self.solution_version}',
            retries ={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

        self.account = self._get_local_account_id()

    def get_connection(self, service, region=None):
        """Connect to AWS api"""

        if not region:
            region = self.region
            
        if service not in self.client:
            self.client[service] = {}

        if region not in self.client[service]:
            self.client[service][region] = boto3.client(service, region_name=region, config=self.boto_config)

        return self.client[service][region]

    def _get_local_account_id(self):
        """
        get local account info
        """
        aws_account_id = self.get_connection('sts',self.region).get_caller_identity().get('Account')
        return aws_account_id

class MissingAssumedRole(Exception):
    pass

class BotoSession:
    client_props = {}
    resource_props = {}
    STS = None
    partition = None
    session = None
    target = None
    role = None

    def create_session(self):
        self.STS = None
        # Local or remote? Who am I?
        self.STS = boto3.client('sts', config=self.boto_config)
        if not self.target:
            self.target = self.STS.get_caller_identity()['Account']
        remote_account = self.STS.assume_role(
            RoleArn='arn:' + self.partition + ':iam::' + self.target + ':role/' + self.role,
            RoleSessionName="sechub_admin"
        )
        self.session = boto3.session.Session(
            aws_access_key_id=remote_account['Credentials']['AccessKeyId'],
            aws_secret_access_key=remote_account['Credentials']['SecretAccessKey'],
            aws_session_token=remote_account['Credentials']['SessionToken']
        )

        boto3.setup_default_session()

    def __init__(self, account=None, role=None, partition=None):
        """
        Create a session
        account: None or the target account
        """
        # Default partition to 'aws'
        if not partition:
            partition = 'aws'
        self.target = account
        if not role:
            raise MissingAssumedRole
        else:
            self.role = role
        self.session = None
        self.partition = os.getenv('AWS_PARTITION', partition)
        self.solution_id = os.getenv('SOLUTION_ID', 'SO0111')
        self.solution_version = os.getenv('SOLUTION_VERSION', 'undefined')
        self.boto_config = Config(
            user_agent_extra=f'AwsSolution/{self.solution_id}/{self.solution_version}',
            retries ={
                'max_attempts': 10,
                'mode': 'standard'
            }
        )
        self.create_session()

    def client(self, name, **kwargs):

        self.client_props[name] = self.session.client(name, config=self.boto_config, **kwargs)
        return self.client_props[name]

    def resource(self, name, **kwargs):

        self.resource_props[name] = self.session.resource(name, config=self.boto_config, **kwargs)
        return self.resource_props[name]
