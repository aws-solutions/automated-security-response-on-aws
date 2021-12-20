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
"""
Check the value of the Lambda Environmental variable RUN_WORKFLOW. If set,
send the remediation input to the member account runbook named in the 
RUN_WORKFLOW variable.

This Lambda can be further modified by the customer to gather additional 
information to determine when to inject RUN_WORKFLOW. Methods are defined
and stubbed out to support this: _is_remediation_destructive(), etc.
"""
import json
import boto3
import os
import re
from botocore.config import Config
from botocore.exceptions import ClientError
from logger import Logger
from awsapi_cached_client import BotoSession
from sechub_findings import Finding
import utils

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
# If env WORKFLOW_RUNBOOK is set and not blank then all remediations will be
# executed through this runbook, if it is present and enabled in the member
# account.
SOLUTION_ID = os.getenv('SOLUTION_ID', 'SO0111')
SOLUTION_ID = re.sub(r'^DEV-', '', SOLUTION_ID)

def _get_ssm_client(account, role, region=''):
    """
    Create a client for ssm
    """
    sess = BotoSession(
        account,
        f'{role}'
    )
    kwargs = {}
    if region:
        kwargs['region_name'] = region

    return sess.client('ssm', **kwargs)

def _is_remediation_destructive(standard, version, control):
    return False

def _is_account_sensitive(accountid):
    return False

def _is_automatic_trigger(event_type):
    if event_type == 'Security Hub Findings - Imported':
        return False
    else:
        return True

def _is_custom_action_trigger(event_type):
    if event_type == 'Security Hub Findings - Imported':
        return True
    else:
        return False

def _get_alternate_workflow(accountid):
    """
    Get the alt workflow based on environmental variables for this lambda
    and whether the alt runbook is active. Note that alt workflow must run
    in the same region as the Step Function.
    """
    running_account = boto3.client('sts').get_caller_identity()['Account']

    # Is an alternate workflow defined?
    WORKFLOW_RUNBOOK = os.getenv('WORKFLOW_RUNBOOK', '')
    WORKFLOW_RUNBOOK_ACCOUNT = os.getenv('WORKFLOW_RUNBOOK_ACCOUNT', 'member')
    WORKFLOW_RUNBOOK_ROLE = os.getenv('WORKFLOW_RUNBOOK_ROLE', '')

    # Disabled by removing the Lambda environmental var or setting to ''
    if not WORKFLOW_RUNBOOK:
        return (None, None, None)

    if WORKFLOW_RUNBOOK_ACCOUNT.lower() == 'member':
        WORKFLOW_RUNBOOK_ACCOUNT = accountid
    elif WORKFLOW_RUNBOOK_ACCOUNT.lower() == 'admin':
        WORKFLOW_RUNBOOK_ACCOUNT = running_account
    else:
        # log an error - bad config
        LOGGER.error(f'WORKFLOW_RUNBOOK_ACCOUNT config error: "{WORKFLOW_RUNBOOK_ACCOUNT}" is not valid. Must be "member" or "admin"')
        return (None, None, None)

    # Make sure it exists and is active
    if _doc_is_active(WORKFLOW_RUNBOOK, WORKFLOW_RUNBOOK_ACCOUNT):  
        return(WORKFLOW_RUNBOOK, WORKFLOW_RUNBOOK_ACCOUNT, WORKFLOW_RUNBOOK_ROLE)
    else:
        return(None, None, None)

def _doc_is_active(doc, account):
    try:
        ssm = _get_ssm_client(account, SOLUTION_ID + '-SHARR-Orchestrator-Member')
        docinfo = ssm.describe_document(
            Name=doc
            )['Document']
        
        doctype = docinfo.get('DocumentType', 'unknown')
        docstate = docinfo.get('Status', 'unknown')

        if doctype == "Automation" and \
           docstate == "Active":
            return True
        else:
            return False

    except ClientError as ex:
        exception_type = ex.response['Error']['Code']
        if exception_type in "InvalidDocument":
            return False
        else:
            LOGGER.error('An unhandled client error occurred: ' + exception_type)
            return False

    except Exception as e:
        LOGGER.error('An unhandled error occurred: ' + str(e))
        return False

def lambda_handler(event, context):
    answer = utils.StepFunctionLambdaAnswer()
    answer.update({
        'workflowdoc': '',
        'workflowaccount': '',
        'workflowrole': '',
        'workflow_data': {
            'impact': 'nondestructive',
            'approvalrequired': 'false'
        }
    })
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

    auto_trigger = _is_automatic_trigger(event['EventType'])
    is_destructive = _is_remediation_destructive(finding.standard_shortname, finding.standard_version, finding.standard_control)
    is_sensitive = _is_account_sensitive(finding.account_id)

    approval_required = 'false'
    remediation_impact = 'nondestructive'
    use_alt_workflow = 'false'

    #
    # PUT ADDITIONAL CRITERIA HERE. When done, remediation_impact and approval_required
    # must be set per your needs
    #----------------------------------------------------------------------------------
    if auto_trigger and is_destructive and is_sensitive:
        remediation_impact = 'destructive'
        approval_required = 'true'
        use_alt_workflow = 'true'

    #----------------------------------------------------------------------------------

    # Is there an alternative workflow configured?
    (alt_workflow, alt_account, alt_role) = _get_alternate_workflow(finding.account_id)

    # If so, update workflow_data
    # ---------------------------
    # workflow_data can be modified to suit your needs. This data is passed to the 
    # alt_workflow. Using the alt_workflow redirects the remediation to your workflow
    # only! The normal SHARR workflow will not be executed.
    #----------------------------------------------------------------------------------
    if alt_workflow and use_alt_workflow:
        answer.update({
            'workflowdoc': alt_workflow,
            'workflowaccount': alt_account,
            'workflowrole': alt_role,
            'workflow_data': {
                'impact': remediation_impact,
                'approvalrequired': approval_required
            }
        })

    return answer.json()
