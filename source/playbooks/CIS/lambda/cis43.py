#!/usr/bin/python
###############################################################################
#  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
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

import os, sys
from botocore.config import Config
from lib.sechub_findings import Finding, notify
from lib.logger import Logger
from lib.awsapi_helpers import AWSClient, BotoSession
from lib.applogger import LogHandler
from lib.metrics import Metrics

#------------------------------
# Remediation-Specific
#------------------------------
LAMBDA_ROLE = 'SO0111_CIS43_memberRole'
REMEDIATION = 'Remove all rules from the default security group'
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
BOTO_CONFIG = Config(
    retries={
        'max_attempts': 10
    },
    region_name=AWS_REGION
)
AWS = AWSClient()

#------------------------------------------------------------------------------
# HANDLER
#------------------------------------------------------------------------------
def lambda_handler(event, context):

    LOGGER.debug(event)
    metrics = Metrics(event)    
    try:
        for finding_rec in event['detail']['findings']:
            finding = Finding(finding_rec)
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
        LOGGER.debug('CIS 4.3: incorrect custom action selection')
        APPLOGGER.add_message('CIS 4.3: incorrect custom action selection')
        return

    if cis_data['ruleid'] not in ['4.3']:
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 4.3: incorrect custom action selection')
        APPLOGGER.add_message('CIS 4.3: incorrect custom action selection')
        return

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
    
    #==========================================================================
    try:
        myDefaultSecGroupId = str(finding.details['Resources'][0]['Details'][sg_type]['GroupId'])
    except KeyError as key:
        LOGGER.error('Could not find ' + str(key) + ' in Resources data for the finding')
        failed()
        return
    except Exception as e:
        LOGGER.error('Unexpected error: ' + str(sys.exc_info()))
        LOGGER.error(e)
        return

    message['AffectedObject'] = AFFECTED_OBJECT + ': ' + myDefaultSecGroupId

    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        ec2 = sess.resource('ec2')
    except Exception as e:
        LOGGER.error('Unexpected error: ' + str(sys.exc_info()))
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    try:
        # sg ec2 resource object
        defaultSG = ec2.SecurityGroup(myDefaultSecGroupId)
        # find ingress + egress rules
        defaultIngress = defaultSG.ip_permissions
        defaultEgress = defaultSG.ip_permissions_egress
        revokeIngress = defaultSG.revoke_ingress(IpPermissions=defaultIngress)
        revokeEgress = defaultSG.revoke_egress(IpPermissions=defaultEgress)
        LOGGER.info(revokeIngress)
        LOGGER.info(revokeEgress)
        message['State'] = 'RESOLVED'
        message['Note'] = '' # Reset the value
        notify(finding, message, LOGGER, cwlogs=APPLOGGER, sns=AWS)
    except Exception as e:
        LOGGER.error('Unexpected error: ' + str(sys.exc_info()))
        LOGGER.error(e)
        failed()
        return
