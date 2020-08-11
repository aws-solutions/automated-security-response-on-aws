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

import datetime
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
LAMBDA_ROLE = 'SO0111_CIS1314_memberRole' # role to use for cross-account
REMEDIATION = 'Deactivate unused keys over 90 days old'
AFFECTED_OBJECT = 'Access Key'
#------------------------------

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
APPLOGGER = LogHandler(os.path.basename(__file__[:-3])) # application logger for CW Logs

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
        LOGGER.debug('CIS 1.3 - 1.4: incorrect custom action selection')
        APPLOGGER.add_message('CIS 1.3 - 1.4: incorrect custom action selection')
        return

    if (cis_data['ruleid'] not in ['1.3','1.4']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 1.3 - 1.4: incorrect custom action selection')
        APPLOGGER.add_message('CIS 1.3 - 1.4: incorrect custom action selection')
        return

    resource_type = str(finding.details['Resources'][0]['Type'])

    if resource_type == 'AwsAccount':
        # This code snippet is invoked when the user selects a finding with type as AwsAccount
        # this finding in security hub is more referring to the account in general and doesn't provide
        # information of the specific remediation, once the specific Resource Type errors are resolved 
        # this finding will be resolved as well, therefore there is no specific remediation for this finding.
        LOGGER.debug('for finding type AwsAccount, there is no resolution.')
        APPLOGGER.add_message('AwsAccount is a general finding for the entire account. Once the specific findings are resolved for resource type(s) other than AwsAccount, \
         this will be marked as resolved.')
        message['State'] = 'INITIAL'
        message['Note'] = 'The finding is related to the AWS account.'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)

        return

    #==========================================================================
    # Import boto3 clients
    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        iam = sess.client('iam')
        iam_resource = sess.resource('iam')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    try:
        non_rotated_key_user = str(finding.details['Resources'][0]['Id'])[31:]
    except KeyError as key:
        LOGGER.error('Could not find ' + str(key) + ' in Resources data for the finding')
        failed()
        return
    except Exception as e:
        LOGGER.error(e)
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    try:
        todays_date_time = datetime.datetime.now(datetime.timezone.utc)

        paginator = iam.get_paginator('list_access_keys')

        for response in paginator.paginate(UserName=non_rotated_key_user):

            for key_metadata in response['AccessKeyMetadata']:
                access_key_id = str(key_metadata['AccessKeyId'])
                key_age_finder = todays_date_time - datetime.datetime.fromisoformat(str(key_metadata['CreateDate']))

                if key_age_finder <= datetime.timedelta(days=90):
                    LOGGER.debug("Access key: " + access_key_id + "is compliant.")
                    # APPLOGGER.add_message("Access key: " + access_key_id + "is compliant.")

                else:
                    message['Note'] = "Access key over 90 days old found: " + access_key_id
                    message['State'] = 'INFO'
                    message['AffectedObject'] = AFFECTED_OBJECT + ': ' + access_key_id
                    notify(finding, message, LOGGER, cwlogs=APPLOGGER, sechub=False)

                    access_key = iam_resource.AccessKey(non_rotated_key_user, access_key_id)
                    # deactivate the key
                    access_key.deactivate()
                    get_key_status = iam.list_access_keys(UserName=non_rotated_key_user,MaxItems=20)
                    for keys in get_key_status['AccessKeyMetadata']:
                        this_access_key_id = str(keys['AccessKeyId'])
                        this_key_status = str(keys['Status'])
                        # find the key Id that matches the exposed key
                        if this_access_key_id == access_key_id and this_key_status == 'Inactive':
                            message['State'] = 'RESOLVED'
                            message['Note'] = 'Remediation completed successfully, create new access keys using IAM console.'
                            notify(finding, message, LOGGER, cwlogs=APPLOGGER, sechub=True, sns=AWS)
                                
    except Exception as e:
        LOGGER.error(e)
        failed()
        return
