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
from json.decoder import JSONDecodeError
import boto3
import os
from botocore.config import Config
from logger import Logger
from awsapi_cached_client import BotoSession
import utils
from metrics import Metrics

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
    #   SSMExecution: {
    #     ExecId: string
    #   }
    # }
    # Returns:
    # {
    #   status: { 'UNKNOWN'|'Pending'|'InProgress'|'Waiting'|'Success'|'TimedOut'|'Cancelling'|'Cancelled'|'Failed' },
    #   message: { '' | string }
    # {

    SSM_EXEC_ID = event['SSMExecution']['ExecId']

    metrics_obj = Metrics(
        event['Metrics'],
        event['EventType']
    )

    metrics_data = metrics_obj.get_metrics_from_finding(event['Finding'])

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
        get_lambda_role(ORCH_ROLE_BASE_NAME, event['SecurityStandard'], AWS_REGION)
    )
    ssm = sess.client('ssm')

    # Check status
    automation_exec_info = ssm.describe_automation_executions(
        Filters=[
            {
                'Key': 'ExecutionId',
                'Values': [
                    SSM_EXEC_ID
                ]
            }
        ]
    )

    ssm_exec_status = automation_exec_info.get("AutomationExecutionMetadataList")[0].get("AutomationExecutionStatus", "ERROR")

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
        if 'ExecutionLog' in response_data:
            return response_data['ExecutionLog'].split('\n')
        else:
            return []

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

    if ssm_exec_status in ('Success', 'TimedOut', 'Cancelled', 'Cancelling', 'Failed'):
        remediation_response = {}
        ssm_outputs = automation_exec_info.get("AutomationExecutionMetadataList")[0].get("Outputs")
        affected_object = get_affected_object(ssm_outputs)
        remediation_response_raw = None

        if 'Remediation.Output' in ssm_outputs:
            remediation_response_raw = ssm_outputs['Remediation.Output']
        elif 'VerifyRemediation.Output' in ssm_outputs:
            remediation_response_raw = ssm_outputs['VerifyRemediation.Output']
        else:
            remediation_response_raw = ['']

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

        status_for_message = ssm_exec_status
        if ssm_exec_status == 'Success':
            remediation_status = get_remediation_status(remediation_response, ssm_exec_status)
            status_for_message = remediation_status
            print(f'Remediation Status: {remediation_status}')

        remediation_message = get_remediation_message(remediation_response, status_for_message)

        remediation_logdata = get_execution_log(remediation_response)

        # FailureMessage is only set when the remediation was another SSM doc, not 
        if "FailureMessage" in automation_exec_info.get("AutomationExecutionMetadataList")[0]:
            remediation_logdata.append(automation_exec_info.get("AutomationExecutionMetadataList")[0].get('FailureMessage'))

        answer.update({
            'status': ssm_exec_status,
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
            'status': ssm_exec_status,
            'remediation_status': 'running',
            'message': 'Waiting for completion',
            'executionid': SSM_EXEC_ID,
            'affected_object': '',
            'logdata': []
        })

    return answer.json()
