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
import boto3
import os
from botocore.config import Config
from botocore.exceptions import ClientError
from logger import Logger
from awsapi_cached_client import BotoSession
from sechub_findings import Finding
import utils

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')   # MUST BE SET in global variables
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')           # MUST BE SET in global variables
ORCH_ROLE_BASE_NAME = 'SO0111-SHARR-Orchestrator-Member'    # role to use for cross-account

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

def _get_ssm_client(account, role, region):
    """
    Create a client for ssm
    """
    sess = BotoSession(
        account,
        f'{role}_{region}'
    )
    return sess.client('ssm')

def lambda_handler(event, context):

    answer = utils.StepFunctionLambdaAnswer()
    LOGGER.info(event)
    if "Finding" not in event or \
       "EventType" not in event:
        answer.update({
            'status':'ERROR',
            'message':'Missing required data in request'
        })
        LOGGER.error(answer.message)
        return answer.json()

    finding = Finding(event['Finding'])

    answer.update({
        'securitystandard': finding.standard_shortname,
        'securitystandardversion': finding.standard_version,
        'controlid': finding.standard_control,
        'standardsupported': finding.standard_version_supported, # string True/False
        'accountid': finding.account_id
    })  

    if finding.standard_version_supported != 'True':
        answer.update({
            'status':'NOTENABLED',
            'message':f'Security Standard is not enabled": "{finding.standard_name} version {finding.standard_version}"'
        })
        return answer.json()

    # Connect to APIs

    ssm = _get_ssm_client(finding.account_id, ORCH_ROLE_BASE_NAME, AWS_REGION)
    
    automation_docid = f'SHARR-{finding.standard_shortname}_{finding.standard_version}_{finding.remediation_control}'
    remediation_role = f'SO0111-Remediate-{finding.standard_shortname}-{finding.standard_version}-{finding.remediation_control}'
    
    answer.update({
        'automationdocid': automation_docid,
        'remediationrole': remediation_role
        })

    # Validate input
    try:
        docinfo = ssm.describe_document(
            Name=automation_docid
            )['Document']

        doctype = docinfo.get('DocumentType', 'unknown')

        if doctype != "Automation":
            answer.update({
                'status':'ERROR',
                'message':'Document Type is not "Automation": ' + str(doctype)
            })
            LOGGER.error(answer.message)

        docstate = docinfo.get('Status', 'unknown')
        if docstate != "Active":
            answer.update({
                'status':'NOTACTIVE',
                'message':'Document Status is not "Active": ' + str(docstate)
            })
            LOGGER.error(answer.message)

        answer.update({
            'status':'ACTIVE'
        })

    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        if exception_type in "InvalidDocument":
            answer.update({
                'status':'NOTFOUND',
                'message': f'Document {automation_docid} does not exist.'
            })
            LOGGER.error(answer.message)
        else:
            answer.update({
                'status':'CLIENTERROR',
                'message':'An unhandled client error occurred: ' + exception_type
            })
            LOGGER.error(answer.message)

    except Exception as e:
        answer.update({
            'status':'ERROR',
            'message':'An unhandled error occurred: ' + str(e)
        })
        LOGGER.error(answer.message)
    
    return answer.json()
