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
import boto3
import os
from botocore.config import Config
from logger import Logger
from awsapi_cached_client import BotoSession
from applogger import LogHandler
import utils

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')   # MUST BE SET in global variables
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')           # MUST BE SET in global variables
ORCH_ROLE_BASE_NAME = 'SO0111-SHARR-Remediation'               # role to use for cross-account

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    }
)

def get_lambda_role(role_base_name, security_standard, controlid, aws_region):
    return role_base_name + '-' + security_standard + '-' + controlid + '_' + aws_region

def lambda_handler(event, context):
    # Expected:
    # {
    #   Finding: {
    #       AwsAccountId: <aws account>,
    #       ControlId: string
    #   },
    #   RemediationRole: string,
    #   AutomationDocId: string
    # }
    # Returns:
    # {
    #   status: { 'UNKNOWN'| string },
    #   message: { '' | string },
    #   executionid: { '' | string }
    # }

    answer = utils.StepFunctionLambdaAnswer()

    if "SecurityStandard" not in event or \
       "ControlId" not in event:
        answer.update({
            'status':'ERROR',
            'message':'Missing required data in request'
        })
        LOGGER.error(answer.message)
        return answer.json()

    if "AwsAccountId" not in event['Finding']:
        answer.update({
            'status':'ERROR',
            'message':'Missing AccountId in request'
        })
        LOGGER.error(answer.message)
        return answer.json()

    # Connect to APIs

    sess = BotoSession(
        event['Finding']['AwsAccountId'],
        get_lambda_role(ORCH_ROLE_BASE_NAME, event['SecurityStandard'], event['ControlId'], AWS_REGION)
    )
    ssm = sess.client('ssm')

    remediation_role = 'arn:' + AWS_PARTITION + ':iam::' + event['Finding']['AwsAccountId'] + \
        ':role/' + event['RemediationRole'] + '_' + AWS_REGION


    exec_id = ssm.start_automation_execution(
        # Launch SSM Doc via Automation
        DocumentName=event['AutomationDocId'],
        Parameters={
            "Finding": [
                json.dumps(event['Finding'])
            ],
            "AutomationAssumeRole": [
                remediation_role
            ]
        }
    )['AutomationExecutionId']

    answer.update({
        'status':'SUCCESS',
        'message': event['ControlId'] +
                   'remediation was successfully invoked via AWS Systems Manager in account ' +
                   event['Finding']['AwsAccountId'] + ': ' + exec_id,
        'executionid': exec_id
    })
    LOGGER.info(answer.message)
        
    return answer.json()
