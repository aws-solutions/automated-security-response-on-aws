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

import json
import re
import os
import boto3
from awsapi_cached_client import AWSCachedClient

AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')

class StepFunctionLambdaAnswer:
    """
    Maintains a hash of AWS API Client connections by region and service
    """
    status = 'init'
    message = ''
    executionid = ''
    affected_object = ''
    remediation_status = ''
    logdata = []
    securitystandard = ''
    securitystandardversion = ''
    standardsupported = ''
    controlid = ''
    accountid = ''
    automationdocid = ''
    remediationrole = ''
    workflowdoc = ''
    workflowaccount = ''
    eventtype = ''
    resourceregion = ''
    workflow_data = {} # Hash for workflow data so that it can be modified in
                       # in the future without changing the source code

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

    def update_securitystandard(self, value):
        """Set securitystandard (string)"""
        self.securitystandard = value

    def update_securitystandardversion(self, value):
        """Set securitystandardversion (string)"""
        self.securitystandardversion = value

    def update_standardsupported(self, value):
        """Set standardsupported (string)"""
        self.standardsupported = value
        
    def update_controlid(self, value):
        """Set controlid (string)"""
        self.controlid = value

    def update_accountid(self, value):
        """Set accountid (string)"""
        self.accountid = value

    def update_automationdocid(self, value):
        """Set automationdocid (string)"""
        self.automationdocid = value

    def update_remediationrole(self, value):
        """Set remediationrole (string)"""
        self.remediationrole = value

    def update_eventtype(self, value):
        """Set eventtype (string)"""
        self.eventtype = value

    def update_workflow_data(self, value):
        """Set eventtype (string)"""
        self.workflow_data = value

    def update_workflowdoc(self, value):
        """Set eventtype (string)"""
        self.workflowdoc = value

    def update_workflowaccount(self, value):
        """Set eventtype (string)"""
        self.workflowaccount = value

    def update_workflowrole(self, value):
        """Set eventtype (string)"""
        self.workflowrole = value
    
    def update_resourceregion(self, value):
        """Set eventtype (string)"""
        self.resourceregion = value

    def update_executionregion(self, value):
        """Set eventtype (string)"""
        self.executionregion = value

    def update_executionaccount(self, value):
        """Set eventtype (string)"""
        self.executionaccount = value

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
        if "securitystandard" in answer_data:
            self.update_securitystandard(answer_data['securitystandard'])
        if "securitystandardversion" in answer_data:
            self.update_securitystandardversion(answer_data['securitystandardversion'])
        if "standardsupported" in answer_data:
            self.update_standardsupported(answer_data['standardsupported'])
        if "controlid" in answer_data:
            self.update_controlid(answer_data['controlid'])
        if "accountid" in answer_data:
            self.update_accountid(answer_data['accountid'])
        if "automationdocid" in answer_data:
            self.update_automationdocid(answer_data['automationdocid'])
        if "remediationrole" in answer_data:
            self.update_remediationrole(answer_data['remediationrole'])
        if "eventtype" in answer_data:
            self.update_eventtype(answer_data['eventtype'])
        if "workflow_data" in answer_data:
            self.update_workflow_data(answer_data['workflow_data'])
        if "workflowdoc" in answer_data:
            self.update_workflowdoc(answer_data['workflowdoc'])
        if "workflowaccount" in answer_data:
            self.update_workflowaccount(answer_data['workflowaccount'])
        if "workflowrole" in answer_data:
            self.update_workflowrole(answer_data['workflowrole'])
        if "resourceregion" in answer_data:
            self.update_resourceregion(answer_data['resourceregion'])
        if "executionregion" in answer_data:
            self.update_executionregion(answer_data['executionregion'])
        if "executionaccount" in answer_data:
            self.update_executionaccount(answer_data['executionaccount'])

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
        raise

def publish_to_sns(topic_name, message, region=''):
    """
    Post a message to an SNS topic
    """
    if not region:
        region = AWS_REGION
    partition = partition_from_region(region)
    AWS = AWSCachedClient(region) # cached client object
    account = boto3.client('sts').get_caller_identity()['Account']

    topic_arn = f'arn:{partition}:sns:{region}:{account}:{topic_name}'

    message_id = AWS.get_connection('sns', region).publish(
        TopicArn=topic_arn,
        Message=message
    ).get('MessageId', 'error')

    return message_id
