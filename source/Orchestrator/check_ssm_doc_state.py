# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import boto3
import os
from botocore.config import Config
from botocore.exceptions import ClientError
from logger import Logger
from awsapi_cached_client import BotoSession
from sechub_findings import Finding
import utils

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

def _add_doc_state_to_answer(doc, account, region, answer):
    # Connect to APIs
    ssm = _get_ssm_client(
        account,
        ORCH_ROLE_NAME,
        region
    )
    # Validate input
    try:
        docinfo = ssm.describe_document(
            Name=doc
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
                'message': f'Document {doc} does not exist.'
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

def lambda_handler(event, _):

    answer = utils.StepFunctionLambdaAnswer() # holds the response to the step function
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
        'standardsupported': finding.standard_version_supported,
        'accountid': finding.account_id,
        'resourceregion': finding.resource_region
    })

    if finding.standard_version_supported != 'True':
        answer.update({
            'status':'NOTENABLED',
            'message':f'Security Standard is not enabled": "{finding.standard_name} version {finding.standard_version}"'
        })
        return answer.json()

    # Is there alt workflow configuration?
    alt_workflow_doc = event.get('Workflow',{}).get('WorkflowDocument', None)

    automation_docid = f'ASR-{finding.standard_shortname}_{finding.standard_version}_{finding.remediation_control}'
    remediation_role = f'SO0111-Remediate-{finding.standard_shortname}-{finding.standard_version}-{finding.remediation_control}'

    answer.update({
        'automationdocid': automation_docid,
        'remediationrole': remediation_role
    })

    # If alt workflow is configured we don't need to check doc state, as we checked
    # it in get_approval_requirement
    if alt_workflow_doc:
        answer.update({
            'status': 'ACTIVE'
        })
    else:
        _add_doc_state_to_answer(
            automation_docid,
            finding.account_id,
            finding.resource_region,
            answer
        )

    return answer.json()
