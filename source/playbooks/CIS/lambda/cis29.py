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
import time
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
LAMBDA_ROLE = 'SO0111_CIS29_memberRole'
REMEDIATION = 'Enable VPC flow logging in all VPCs'
AFFECTED_OBJECT = 'VPC Flow Logs'
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
        'AffectedObject': AFFECTED_OBJECT,
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
        LOGGER.debug('CIS 2.9: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 2.9: incorrect custom action selection.')
        return

    if (cis_data['ruleid'] not in ['2.9']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 2.9: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 2.9: incorrect custom action selection.')
        return

    resource_type = str(finding.details['Resources'][0]['Type'])
    if resource_type == 'AwsAccount':
        # This code snippet is invoked when the user selects a finding with type as AwsAccount
        # this finding in security hub is more referring to the account in general and doesn't provide
        # information of the specific security group, once the specific security group errors are resolved 
        # this finding will be resolved as well, therefore there is no specific remediation for this finding.
        LOGGER.debug('for finding resource type AwsAccount, there is no resolution.')
        APPLOGGER.add_message('AwsAccount is a general finding for the entire account. Once the specific findings are resolved for resource type(s) other than AwsAccount, \
         this will be marked as resolved.')
        message['State'] = 'INITIAL'
        message['Note'] = 'The finding is related to the AWS account.'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)
        return

    #==========================================================================
    # Grab non-logged VPC ID from Security Hub finding
    try:
        noncompliantVPC = str(finding.details['Resources'][0]['Id']).split(':')[5].split('/')[1]

        message['AffectedObject'] = AFFECTED_OBJECT + ' for VPC: ' + noncompliantVPC
    except Exception as e:
        message['Note'] = str(e) + ' - Finding format is not as expected.'
        message['State'] = 'FAILED'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)
        return

    lambdaFunctionSeshToken = os.getenv('AWS_SESSION_TOKEN', '')  

    # Get Flow Logs Role ARN from env vars
    DeliverLogsPermissionArn = 'arn:' + AWS_PARTITION + ':iam::' + finding.account_id + \
        ':role/SO0111_CIS29_remediationRole_' + AWS_REGION

    # Import boto3 clients
    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        cwl = sess.client('logs')
        ec2 = sess.client('ec2')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)
       
    # set dynamic variable for CW Log Group for VPC Flow Logs
    vpcFlowLogGroup = "VPCFlowLogs/" + noncompliantVPC + lambdaFunctionSeshToken[0:32]        
    # create cloudwatch log group
    try:
        create_log_grp = cwl.create_log_group(logGroupName=vpcFlowLogGroup)
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # wait for CWL creation to propagate
    time.sleep(3)
    # create VPC Flow Logging
    try:
        enableFlowlogs = ec2.create_flow_logs(
            DryRun=False,
            DeliverLogsPermissionArn=DeliverLogsPermissionArn,
            LogGroupName=vpcFlowLogGroup,
            ResourceIds=[noncompliantVPC],
            ResourceType='VPC',
            TrafficType='REJECT',
            LogDestinationType='cloud-watch-logs'
        )
        LOGGER.debug(enableFlowlogs)
    except Exception as e:
        failed()
        LOGGER.error(e)
        return

    # wait for Flow Log creation to propogate
    time.sleep(2)
    # searches for flow log status, filtered on unique CW Log Group created earlier
    try:
        confirmFlowlogs = ec2.describe_flow_logs(
            DryRun=False,
            Filters=[
                {
                    'Name': 'log-group-name',
                    'Values': [vpcFlowLogGroup]
                },
            ]
        )
        LOGGER.debug(confirmFlowlogs)
        flowStatus = str(confirmFlowlogs['FlowLogs'][0]['FlowLogStatus'])
        if flowStatus == 'ACTIVE':
            message['Note'] = '\"' + REMEDIATION + '\" remediation was successful'
            message['State'] = 'RESOLVED'
            notify(finding, message, LOGGER, cwlogs=APPLOGGER, sns=AWS)
        else:
            failed()
            LOGGER.error(e)
            return

    except Exception as e:
        LOGGER.error(e)
        failed()
        return
