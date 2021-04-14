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

import os
import json
import uuid
import requests
import hashlib
from urllib.request import Request, urlopen
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

class Metrics(object):

    event_type = ''
    send_metrics_option = 'No'
    solution_version = ''
    solution_uuid = None
    session = None
    region = None
    ssm_client = None
    metrics_parameter_name = '/Solutions/SO0111/anonymous_metrics_uuid'

    def __update_solution_uuid(self, new_uuid):
        ssm = boto3.client('ssm')
        ssm.put_parameter(
            Name=self.metrics_parameter_name,
            Description='Unique Id for anonymous metrics collection',
            Value=new_uuid,
            Type='String'
        )

    def __init__(self, metrics_options, event):
        self.session = boto3.session.Session()
        self.region = self.session.region_name

        if 'sendAnonymousMetrics' in metrics_options:
            self.send_metrics_option = metrics_options.get('sendAnonymousMetrics','No')
        if 'detail-type' in event:
            self.event_type = event.get('detail-type')

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
            return boto3.client('ssm', self.region)

    def __update_solution_uuid(self, new_uuid):
        self.ssm_client.put_parameter(
            Name=self.metrics_parameter_name,
            Description='Unique Id for anonymous metrics collection',
            Value=new_uuid,
            Type='String'
        )

    def __get_solution_uuid(self):
        try:
            solution_uuid_from_ssm = self.ssm_client.get_parameter(
                Name=self.metrics_parameter_name
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
                    'region': self.region
                }
            else:
                metrics_data = {}
            return metrics_data
        except Exception as excep:
            print(excep)
            return {}

    def send_metrics(self, metrics_data):

        try:
            if metrics_data is not None and self.send_metrics_option.lower() == 'yes':
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
                return
        except Exception as excep:
            print(excep)

    def post_metrics_to_api(self, request_data):
        url = 'https://metrics.awssolutionsbuilder.com/generic'
        req = Request(url, method='POST', data=bytes(json.dumps(
            request_data), encoding='utf8'), headers={'Content-Type': 'application/json'})
        urlopen(req)
