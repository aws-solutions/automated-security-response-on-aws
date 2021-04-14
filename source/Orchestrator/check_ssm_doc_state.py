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
from botocore.exceptions import ClientError
from logger import Logger
from awsapi_cached_client import BotoSession
import utils

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')   # MUST BE SET in global variables
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')           # MUST BE SET in global variables
ORCH_ROLE_BASE_NAME = 'SO0111-SHARR-Orchestrator-Member'               # role to use for cross-account

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    }
)

def get_lambda_role(role_base_name, security_standard, aws_region):
    return role_base_name + '-' + security_standard + '_' + aws_region

def lambda_handler(event, context):
    # Expected:
    # {
    #   Finding: {
    #       AwsAccountId: <aws account>
    #   },
    #   AutomationDocId: <name>
    # }
    # Returns:
    # {
    #   status: { 'UNKNOWN' | string },
    #   message: { '' | string }
    # }

    answer = utils.StepFunctionLambdaAnswer()

    LOGGER.info(event)

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
            'message':'Missing AccountId in request Finding data'
        })
        LOGGER.error(answer.message)
        return answer.json()

    # Connect to APIs

    sess = BotoSession(
        event["Finding"]["AwsAccountId"], 
        get_lambda_role(ORCH_ROLE_BASE_NAME, event['SecurityStandard'], AWS_REGION)
    )
    ssm = sess.client('ssm')

    # Validate input
    try:
        docinfo = ssm.describe_document(
            Name=event["AutomationDocId"]
        ).get("Document")

        doctype = docinfo.get('DocumentType', 'unknown')
        if doctype != "Automation":
            answer.update({
                'status':'ERROR',
                'message':'Document Type is not "Automation": ' + str(doctype)
            })
            LOGGER.error(answer.message)
            return answer.json()

        docstate = docinfo.get('Status', 'unknown')
        if docstate != "Active":
            answer.update({
                'status':'NOTACTIVE',
                'message':'Document Status is not "Active": ' + str(docstate)
            })
            LOGGER.error(answer.message)
            return answer.json()

        answer.update({
            'status':'ACTIVE'
        })
        return answer.json()

    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        # stream did exist but need new token, get it from exception data
        if exception_type in "InvalidDocument":
            answer.update({
                'status':'NOTFOUND',
                'message':'Document ' + event["AutomationDocId"] + ' does not exist.'
            })
            LOGGER.error(answer.message)
            return json.dumps(answer)
        else:
            answer.update({
                'status':'CLIENTERROR',
                'message':'An unhandled client error occurred: ' + exception_type
            })
            LOGGER.error(answer.message)
            return answer.json()

    except Exception as e:
        answer.update({
            'status':'ERROR',
            'message':'An unhandled error occurred: ' + str(e)
        })
        LOGGER.error(answer.message)
        return answer.json()
