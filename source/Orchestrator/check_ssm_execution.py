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
from json.decoder import JSONDecodeError
import boto3
import os
from botocore.config import Config
from logger import Logger
from awsapi_cached_client import BotoSession
from sechub_findings import Finding
import utils
from metrics import Metrics

ORCH_ROLE_NAME = 'SO0111-SHARR-Orchestrator-Member'    # role to use for cross-account

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)

def _get_ssm_client(account, role, region=''):
    """
    Create a client for ssm
    """
    kwargs = {}

    if region:
        kwargs['region_name'] = region

    return BotoSession(
        account,
        f'{role}'
    ).client('ssm', **kwargs)

class ParameterError(Exception):
    error = 'Invalid parameter input'
    def __init__(self, error=''):
        if error:
            self.error = error
        super().__init__(self.error)

    def __str__(self):
        return f'{self.error}'

class AutomationExecution(object):
    status = None
    outputs = {}
    failure_message = None
    exec_id = None
    account = None
    role_base_name = None
    region = None # Region where the ssm doc is running
    _ssm_client = None

    def __init__(self, exec_id, account, role_base_name, region):
        if not re.match('^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', exec_id):
            raise ParameterError(f'Invalid Automation Execution Id: {exec_id}')
        self.exec_id = exec_id
        if not re.match('^[0-9]{12}$', account):
            raise ParameterError(f'Invalid Value for Account: {account}')
        self.account = account
        if not re.match('^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$', region):
            raise ParameterError(f'Invalid Value for Region: {region}')
        self.region = region
        if not re.match('^[a-zA-Z0-9_+=,.@-]{1,64}$', role_base_name):
            raise ParameterError(f'Invalid Value for Role_Base_Name: {role_base_name}')

        self._ssm_client = _get_ssm_client(self.account, role_base_name, self.region)
        self.get_execution_state()

    def get_execution_state(self):
        automation_exec_info = self._ssm_client.describe_automation_executions(
            Filters=[
                {
                    'Key': 'ExecutionId',
                    'Values': [
                        self.exec_id
                    ]
                }
            ]
        )

        self.status = automation_exec_info.get(
            "AutomationExecutionMetadataList"
        )[0].get(
            "AutomationExecutionStatus", 
            "ERROR"
        )

        self.outputs = automation_exec_info.get(
            "AutomationExecutionMetadataList"
        )[0].get(
            "Outputs", 
            {}
        )
        
        if 'Remediation.Output' in self.outputs and \
            isinstance(self.outputs['Remediation.Output'], list) and \
            len(self.outputs['Remediation.Output']) == 1 and \
            self.outputs['Remediation.Output'][0] == "No output available yet because the step is not successfully executed":
                self.outputs['Remediation.Output'][0] = "See Automation Execution output for details"

        self.failure_message = automation_exec_info.get(
            "AutomationExecutionMetadataList"
        )[0].get(
            "FailureMessage", 
            ""
        )

def valid_automation_doc(automation_doc):
    return "SecurityStandard" in automation_doc and \
       "ControlId" in automation_doc and \
       "AccountId" in automation_doc

def lambda_handler(event, context):
    answer = utils.StepFunctionLambdaAnswer()
    automation_doc = event['AutomationDocument']

    if not valid_automation_doc(automation_doc):
        answer.update({
            'status':'ERROR',
            'message':'Missing AutomationDocument data in request: ' + json.dumps(automation_doc)
        })
        LOGGER.error(answer.message)
        return answer.json()

    SSM_EXEC_ID = event['SSMExecution']['ExecId']
    SSM_ACCOUNT = event['SSMExecution'].get('Account')
    SSM_REGION = event['SSMExecution'].get('Region')

    if not SSM_ACCOUNT or not SSM_REGION:
        exit('ERROR: missing remediation account information. SSMExecution missing region or account.')

    finding = Finding(event['Finding'])

    metrics_obj = Metrics(
        event['EventType']
    )
    metrics_data = metrics_obj.get_metrics_from_finding(event['Finding'])

    try:
        automation_exec_info = AutomationExecution(SSM_EXEC_ID, SSM_ACCOUNT, ORCH_ROLE_NAME, SSM_REGION)
    except Exception as e:
        LOGGER.error(f'Unable to retrieve AutomationExecution data: {str(e)}')
        raise e

    # Terminal states - get log data from AutomationExecutionMetadataList
    #
    # AutomationExecutionStatus - was the ssm doc successful? (did it not blow up)
    # Outputs - 
    #   ParseInput.AffectedObject - what was the finding asserted on? Can be a string value or a dict
    #       Ex. 111111111111 - AWS AccountId
    #       Ex { 'Type': string, 'Id': string }
    #   VerifyRemediation.Output or Remediation.Output - what the script, if any, returned
    #       ExecutionLog: stdout from the script, added automatically when there is a return statement
    #       response: returned by the script itself.
    #           status: [SUCCESS|FAILED] - did the REMEDIATION succeed?
    #   VerifyRemediation.Output or Remediation.Output may be a string, when using a child runbook for 
    #       remediation.
    
    def get_execution_log(response_data):
        logdata = []
        if 'ExecutionLog' in response_data:
            logdata = response_data['ExecutionLog'].split('\n')

        return logdata

    def get_affected_object(response_data):
        affected_object_out = 'UNKNOWN'
        if "ParseInput.AffectedObject" in response_data:
            affected_object = response_data.get('ParseInput.AffectedObject')[0]
            try:
                affected_object = json.loads(affected_object)
                if 'Type' in affected_object and 'Id' in affected_object:
                    affected_object_out = affected_object['Type'] + ' ' + affected_object['Id']
                else:
                    affected_object_out = str(affected_object)
            except JSONDecodeError:
                print('Expected serialized json, got ' + str(affected_object))
                affected_object_out = str(affected_object)
                
        return affected_object_out

    def get_remediation_status(response_data, exec_status):
        status = exec_status
        if 'Payload' in response_data and 'response' in response_data['Payload']:
            status = response_data['Payload']['response'].get('status', 'UNKNOWN')
        elif 'status' in response_data:
            status = response_data['status']
        return status

    def get_remediation_message(response_data, remediation_status):
        message = f'Remediation status: {remediation_status} - please verify remediation'
        if 'Payload' in response_data and 'response' in response_data['Payload']:
            message = response_data['Payload']['response'].get('status', 'UNKNOWN')
        elif 'message' in response_data:
            message = response_data['message']
        return message

    if automation_exec_info.status in ('Success', 'TimedOut', 'Cancelled', 'Cancelling', 'Failed'):
        remediation_response = {}
        ssm_outputs = automation_exec_info.outputs
        affected_object = get_affected_object(ssm_outputs)
        remediation_response_raw = None

        if 'Remediation.Output' in ssm_outputs:
            remediation_response_raw = ssm_outputs['Remediation.Output']
        elif 'VerifyRemediation.Output' in ssm_outputs:
            remediation_response_raw = ssm_outputs['VerifyRemediation.Output']
        else:
            remediation_response_raw = json.dumps(ssm_outputs)

        # Remediation.Response is a list, if present. Only the first item should exist. 
        if isinstance(remediation_response_raw, list):
            try:
                remediation_response = json.loads(remediation_response_raw[0])
            except JSONDecodeError:
                remediation_response = {"message": remediation_response_raw[0]}
            except Exception as e:
                print(e)
                print('Unhandled error')
        elif isinstance(remediation_response_raw, str):
            remediation_response = { "message": remediation_response_raw}

        status_for_message = automation_exec_info.status
        if automation_exec_info.status == 'Success':
            remediation_status = get_remediation_status(remediation_response, automation_exec_info.status)
            status_for_message = remediation_status
            print(f'Remediation Status: {remediation_status}')

        remediation_message = get_remediation_message(remediation_response, status_for_message)

        remediation_logdata = get_execution_log(remediation_response)

        # FailureMessage is only set when the remediation was another SSM doc, not 
        if automation_exec_info.failure_message:
            remediation_logdata.append(automation_exec_info.failure_message)

        answer.update({
            'status': automation_exec_info.status,
            'remediation_status': status_for_message,
            'message': remediation_message,
            'executionid': SSM_EXEC_ID,
            'affected_object': affected_object,
            'logdata': json.dumps(remediation_logdata, default=str)
        })

        try:
            metrics_data['status'] = status_for_message
            metrics_obj.send_metrics(metrics_data)
        except Exception as e:
            LOGGER.error(e)
            LOGGER.error('Failed to send metrics')

    else:

        answer.update({
            'status': automation_exec_info.status,
            'remediation_status': 'running',
            'message': 'Waiting for completion',
            'executionid': SSM_EXEC_ID,
            'affected_object': '',
            'logdata': []
        })

    return answer.json()
