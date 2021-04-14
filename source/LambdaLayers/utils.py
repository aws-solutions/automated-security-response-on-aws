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

import json
import re
from awsapi_cached_client import AWSCachedClient

class StepFunctionLambdaAnswer:
    """
    Maintains a hash of AWS API Client connections by region and service
    """
    status = ''
    message = ''
    executionid = ''
    affected_object = ''
    remediation_status = ''
    logdata = []

    def __init__(self):
        """Set message and status - minimum required fields"""
        self.status = ''
        self.message = ''
        self.remediation_status = ''
        self.logdata = []

    def __str__(self):
        return json.dumps(self.__dict__)

    def json(self):
        return self.__dict__

    def update_status(self, status):
        """Set status"""
        self.status = status

    def update_message(self, message):
        """Set status"""
        self.message = message

    def update_logdata(self, logdata):
        """Set logdata (list)"""
        self.logdata = logdata

    def update_executionid(self, executionid):
        """Set execution id (string)"""
        self.executionid = executionid

    def update_affected_object(self, affected_object):
        """Set affected_object (string)"""
        self.affected_object = affected_object

    def update_remediation_status(self, status):
        """Set execution id (string)"""
        self.remediation_status = status

    def update(self, answer_data):
        if "status" in answer_data:
            self.update_status(answer_data['status'])
        if "message" in answer_data:
            self.update_message(answer_data['message'])
        if "remediation_status" in answer_data:
            self.update_remediation_status(answer_data['remediation_status'])
        if "logdata" in answer_data:
            self.update_logdata(answer_data['logdata'])
        if "executionid" in answer_data:
            self.update_executionid(answer_data['executionid'])
        if "affected_object" in answer_data:
            self.update_affected_object(answer_data['affected_object'])

def resource_from_arn(arn):
    """
    Strip off the leading parts of the ARN: arn:*:*:*:*:
    Return what's left. If no match, return the original predicate.
    """
    arn_pattern = re.compile(r'arn\:[\w,-]+:[\w,-]+:.*:[0-9]*:(.*)')
    arn_match = arn_pattern.match(arn)
    answer = arn
    if arn_match:
        answer = arn_match.group(1)
    return answer

def partition_from_region(region_name):
    """
    returns the partition for a given region
    Note: this should be a Boto3 function and should be deprecated once it is.
    On success returns a string
    On failure returns NoneType
    """

    parts = region_name.split('-')
 
    try:
        if parts[0] == 'us' and parts[1] == 'gov':
            return 'aws-us-gov'
        elif parts[0] == 'cn':
            return 'aws-cn'
        else:
            return 'aws'
    except:
        return

def publish_to_sns(topic_name, message, region=None):
    """
    Post a message to an SNS topic
    """
    AWS = AWSCachedClient(region) # cached client object

    partition = None

    if region:
        partition = partition_from_region(region)
    else:
        partition = 'aws'
        region = 'us-east-1'

    topic_arn = 'arn:' + partition + ':sns:' + region + ':' + AWS.account + ':' + topic_name

    json_message = json.dumps({"default":json.dumps(message)})
    message_id = AWS.get_connection('sns', region).publish(
        TopicArn=topic_arn,
        Message=json_message,
        MessageStructure='json'
    ).get('MessageId', 'error')

    return message_id
