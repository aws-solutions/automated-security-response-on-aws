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

import os
import json
import uuid
import requests
import hashlib
from urllib.request import Request, urlopen
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

SEND_METRICS = os.environ.get('sendAnonymousMetrics', 'No')
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')

class Metrics(object):

    event_type = ''
    solution_uuid = 'error'
    solution_version = 'unknown'
    ssm_client = None

    def __init__(self, event):
        try:
            self.event_type = event.get('detail-type')
        except Exception as excep:
            print(excep)

        self.ssm_client = self.connect_to_ssm()
        self.__get_solution_uuid()

        try:
            solution_version_parm = '/Solutions/SO0111/version'
            solution_version_from_ssm = self.ssm_client.get_parameter(
                Name=solution_version_parm
            ).get('Parameter').get('Value')
        except ClientError as ex:
            exception_type = ex.response['Error']['Code']
            if exception_type == 'ParameterNotFound':
                solution_version_from_ssm = 'unknown'
            else:
                print(ex)
        except Exception as e:
            print(e)
            raise

        self.solution_version = solution_version_from_ssm

    def connect_to_ssm(self):
        if self.ssm_client:
            return self.ssm_client
        else:
            return boto3.client('ssm', AWS_REGION)

    def __update_solution_uuid(self, new_uuid):
        self.ssm_client.put_parameter(
            Name='/Solutions/SO0111/anonymous_metrics_uuid',
            Description='Unique Id for anonymous metrics collection',
            Value=new_uuid,
            Type='String'
        )

    def __get_solution_uuid(self):
        try:
            solution_uuid_from_ssm = self.ssm_client.get_parameter(
                Name='/Solutions/SO0111/anonymous_metrics_uuid'
            ).get('Parameter').get('Value')
            self.solution_uuid = solution_uuid_from_ssm
        except ClientError as ex:
            exception_type = ex.response['Error']['Code']
            if exception_type == 'ParameterNotFound':
                self.solution_uuid = str(uuid.uuid4())
                self.__update_solution_uuid(self.solution_uuid)
            else:
                print(ex)
                raise
        except Exception as e:
            print(e)
            raise

    def get_metrics_from_finding(self, finding):

        try:
            if finding is not None:
                metrics_data = {
                    'generator_id': finding.get('GeneratorId'),
                    'type': finding.get('Title'),
                    'productArn': finding.get('ProductArn'),
                    'finding_triggered_by': self.event_type,
                    'region': AWS_REGION
                }
            else:
                metrics_data = {}
            return metrics_data
        except Exception as excep:
            print(excep)
            return {}

    def send_metrics(self, metrics_data):

        try:
            if metrics_data is not None and SEND_METRICS.lower() == 'yes':
                usage_data = {
                    'Solution': 'SO0111',
                    'UUID': self.solution_uuid,
                    'TimeStamp': str(datetime.utcnow().isoformat()),
                    'Data': metrics_data,
                    'Version': self.solution_version
                }
                print(f'Sending metrics data {json.dumps(usage_data)}')
                self.post_metrics_to_api(usage_data)
                
            else:
                print(f'Send Metrics = {SEND_METRICS}')
                return
        except Exception as excep:
            print(excep)
        return

    def post_metrics_to_api(self, request_data):
        url = 'https://metrics.awssolutionsbuilder.com/generic'
        req = Request(url, method='POST', data=bytes(json.dumps(
            request_data), encoding='utf8'), headers={'Content-Type': 'application/json'})
        rsp = urlopen(req)
        rspcode = rsp.getcode()
        return
