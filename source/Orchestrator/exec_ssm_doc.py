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
import os
import re
import boto3
from botocore.exceptions import ClientError
from logger import Logger
from awsapi_cached_client import BotoSession
from applogger import LogHandler
import utils

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')   # MUST BE SET in global variables
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')           # MUST BE SET in global variables
SOLUTION_ID = os.getenv('SOLUTION_ID', 'SO0111')
SOLUTION_ID = re.sub(r'^DEV-', '', SOLUTION_ID)
SOLUTION_VERSION = os.getenv('SOLUTION_VERSION', 'undefined')

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

def _get_ssm_client(accountid, role):
    """
    Create a client for ssm
    """
    return BotoSession(
        accountid,
        role
    ).client('ssm')


def _get_iam_client(accountid, role):
    """
    Create a client for iam
    """
    return BotoSession(
        accountid,
        role
    ).client('iam')

def lambda_role_exists(client, rolename):
    try:
        client.get_role(
            RoleName=rolename
        )
        return True
    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        if exception_type in "NoSuchEntity":
            return False
        else:
            exit('An unhandled client error occurred: ' + exception_type)
    except Exception as e:
        exit('An unhandled error occurred: ' + str(e))

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

    automation_doc = event['AutomationDocument']

    if "SecurityStandard" not in automation_doc or \
       "ControlId" not in automation_doc or \
       "AccountId" not in automation_doc:
        answer.update({
            'status':'ERROR',
            'message':'Missing AutomationDocument data in request: ' + json.dumps(automation_doc)
        })
        LOGGER.error(answer.message)
        return answer.json()

    orchestrator_member_role = SOLUTION_ID + '-SHARR-Orchestrator-Member_' + AWS_REGION
    standard_role = automation_doc['RemediationRole'] + '_' + AWS_REGION

    # If the standard/version/control has a specific role defined then use it
    # Otherwise, use the Orchestrator Member role
    remediation_role = orchestrator_member_role
    iam = _get_iam_client(automation_doc['AccountId'], remediation_role)

    if lambda_role_exists(iam, standard_role):
        remediation_role = standard_role

    print(f'Using role {remediation_role} for remediation in {automation_doc["AccountId"]} document {automation_doc["AutomationDocId"]}')
    remediation_role_arn = 'arn:' + AWS_PARTITION + ':iam::' + automation_doc['AccountId'] + \
        ':role/' + remediation_role
    print(f'ARN: {remediation_role_arn}')
    
    ssm = _get_ssm_client(automation_doc['AccountId'], remediation_role)
  
    exec_id = ssm.start_automation_execution(
        # Launch SSM Doc via Automation
        DocumentName=automation_doc['AutomationDocId'],
        Parameters={
            "Finding": [
                json.dumps(event['Finding'])
            ],
            "AutomationAssumeRole": [
                remediation_role_arn
            ]
        }
    )['AutomationExecutionId']

    answer.update({
        'status':'SUCCESS',
        'message': automation_doc['ControlId'] +
                   ' remediation was successfully invoked via AWS Systems Manager in account ' +
                   automation_doc['AccountId'] + ': ' + exec_id,
        'executionid': exec_id
    })
    LOGGER.info(answer.message)
        
    return answer.json()
