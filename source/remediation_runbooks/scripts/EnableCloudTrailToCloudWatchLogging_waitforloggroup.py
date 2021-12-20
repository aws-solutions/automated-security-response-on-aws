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

import boto3
from botocore.config import Config
import time

def connect_to_logs(boto_config):
    return boto3.client('logs', config=boto_config)

def wait_for_loggroup(event, context):
    boto_config = Config(
        retries ={
          'mode': 'standard'
        }
    )
    cwl_client = connect_to_logs(boto_config)

    max_retries = 3
    attempts = 0
    while attempts < max_retries:
        try:
            describe_group = cwl_client.describe_log_groups(logGroupNamePrefix=event['LogGroup'])
            print(len(describe_group['logGroups']))
            for group in describe_group['logGroups']:
                if group['logGroupName'] == event['LogGroup']:
                    return str(group['arn'])
            # no match - wait and retry
            time.sleep(2)
            attempts += 1

        except Exception as e:
            exit(f'Failed to create Log Group {event["LogGroup"]}: {str(e)}')

    exit(f'Failed to create Log Group {event["LogGroup"]}: Timed out')

