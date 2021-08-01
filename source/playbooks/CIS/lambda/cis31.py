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
from lib.ci3x_common import common_function

# ------------------------------
# Remediation-Specific
# ------------------------------
LAMBDA_ROLE = 'SO0111_CIS31_memberRole'
REMEDIATION = 'Create a log metric filter and alarm for unauthorized API calls'
AFFECTED_OBJECT = 'CloudTrail'
# ------------------------------

PLAYBOOK = os.path.basename(__file__[:-3])
# initialise LOGGERs
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
APPLOGGER = LogHandler(PLAYBOOK)  # application LOGGER for CW Logs

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


# ------------------------------------------------------------------------------
# HANDLER
# ------------------------------------------------------------------------------
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

    APPLOGGER.flush()  # flush the buffer to CW Logs


# ------------------------------------------------------------------------------
# REMEDIATION
# ------------------------------------------------------------------------------
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
        LOGGER.debug('CIS 3.1: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 3.1: incorrect custom action selection.')
        return

    if (cis_data['ruleid'] not in ['3.1']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 3.1: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 3.1: incorrect custom action selection.')
        return

    try:
        print('Testing CIS 3.1')
        x = common_function()
        print(x)
    # Import boto3 clients
    except Exception as e:
        LOGGER.error(e)
        return

    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        cwl = sess.client('logs')
        ec2 = sess.client('ec2')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    #     message['State'] = 'INITIAL'
    #     notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    # wait for CWL creation to propagate

    # except Exception as e:
    #     LOGGER.error(e)
    #     failed()
    #     return
