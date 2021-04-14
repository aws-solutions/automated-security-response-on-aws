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

import os
import boto3
from botocore.config import Config
from lib.sechub_findings import Finding, notify
from lib.logger import Logger
from lib.awsapi_helpers import AWSClient, BotoSession
from lib.applogger import LogHandler
from lib.metrics import Metrics

#------------------------------
# Remediation-Specific
#------------------------------
LAMBDA_ROLE = 'SO0111_CIS4142_memberRole'
REMEDIATION = 'Block global access to port 22 and 3389'
AFFECTED_OBJECT = 'Security Group'
#------------------------------

PLAYBOOK = os.path.basename(__file__[:-3])
# initialise LOGGERs
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
APPLOGGER = LogHandler(PLAYBOOK) # application LOGGER for CW Logs


# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
AWS_PARTITION = os.getenv('AWS_PARTITION', 'aws')

# Append region name to LAMBDA_ROLE
LAMBDA_ROLE += '_' + AWS_REGION
BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    },
    region_name=AWS_REGION
)
AWS = AWSClient(AWS_PARTITION, AWS_REGION)

#------------------------------------------------------------------------------
# HANDLER
#------------------------------------------------------------------------------
def lambda_handler(event, context):

    LOGGER.debug(event)
    metrics = Metrics(event)
    try:
        for finding_rec in event['detail']['findings']:
            finding = Finding(finding_rec)
            LOGGER.info('FINDING_ID: ' + str(finding.details.get('Id')))
            remediate(finding, metrics.get_metrics_from_finding(finding_rec))
    except Exception as e:
        LOGGER.error(e)

    APPLOGGER.flush() # flush the buffer to CW Logs
    
#------------------------------------------------------------------------------
# REMEDIATION
#------------------------------------------------------------------------------
def remediate(finding, metrics_data):

    message = {
        'Note': '',
        'State': 'INFO',
        'Account': finding.account_id,
        'Remediation': REMEDIATION,
        'metrics_data': metrics_data
    }

    def failed():
        """
        Send Failed status message
        """
        message['State'] = 'FAILED'
        message['Note'] = ''
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    # Make sure it matches - custom action can be initiated for any finding.
    # Ignore if the finding selected and the playbook do not match
    cis_data = finding.is_cis_ruleset()
    if not cis_data:
        # Not an applicable finding - does not match ruleset
        # send an error and exit
        LOGGER.debug('CIS 4.1 - 4.2: incorrect custom action selection')
        APPLOGGER.add_message('CIS 4.1 - 4.2: incorrect custom action selection')
        return

    if (cis_data['ruleid'] not in ['4.1', '4.2']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 4.1 - 4.2: incorrect custom action selection')
        APPLOGGER.add_message('CIS 4.1 - 4.2: incorrect custom action selection')
        return

    #==========================================================================
    # parse Security Group ID from Security Hub CWE
    sg_type = str(finding.details['Resources'][0]['Type'])
    if sg_type == 'AwsAccount':
        # This code snippet is invoked when the user selects a finding with type as AwsAccount
        # this finding in security hub is more referring to the account in general and doesn't provide
        # information of the specific security group, once the specific security group errors are resolved 
        # this finding will be resolved as well, therefore there is no specific remediation for this finding.
        LOGGER.debug('for security group finding type AwsAccount, there is no resolution.')
        APPLOGGER.add_message('AwsAccount is a general finding for the entire account. Once the specific findings are resolved for resource type(s) other than AwsAccount, \
         this will be marked as resolved.')
        message['State'] = 'INITIAL'
        message['Note'] = 'The finding is related to the AWS account.'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)
        return

    try:
        non_compliant_sg = str(finding.details['Resources'][0]['Details'][sg_type]['GroupId'])
    except Exception as e:
        message['Note'] = str(e) + ' - Finding format is not as expected.'
        message['State'] = 'FAILED'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)
        return

    message['AffectedObject'] = AFFECTED_OBJECT + ': ' + non_compliant_sg

    #import boto3 clients
    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        ssm = sess.client('ssm')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)
    
    try:
        response = ssm.start_automation_execution(
            # Launch SSM Doc via Automation
            DocumentName='AWS-DisablePublicAccessForSecurityGroup',
            DocumentVersion='1',
            Parameters={
                'GroupId': [ non_compliant_sg ],
                'AutomationAssumeRole': ['arn:' + AWS_PARTITION + ':iam::' + \
                    finding.account_id + ':role/' + LAMBDA_ROLE]
            }
        )
        LOGGER.debug(response)
        message['Note'] = '\"' + REMEDIATION + '\" remediation was successfully invoked via AWS Systems Manager'
        message['State'] = 'RESOLVED'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER, sns=AWS)

    except Exception as e:
        LOGGER.error(e)
        failed()
        return
