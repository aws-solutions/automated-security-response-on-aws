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
import json
import uuid
from botocore.config import Config
from lib.sechub_findings import Finding, notify
from lib.logger import Logger
from lib.awsapi_helpers import AWSClient, BotoSession
from lib.applogger import LogHandler
from lib.metrics import Metrics

#------------------------------
# Remediation-Specific
#------------------------------
LAMBDA_ROLE = 'SO0111_CIS120_memberRole'
REMEDIATION = 'Ensure a support role has been created to manage incidents with AWS Support'
AFFECTED_OBJECT = 'IAM User'
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

    LOGGER.info(event)
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
        LOGGER.debug('CIS 1.20: incorrect custom action selection')
        APPLOGGER.add_message('CIS 1.20: incorrect custom action selection')
        return

    if (cis_data['ruleid'] not in ['1.20']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 1.20: incorrect custom action selection')
        APPLOGGER.add_message('CIS 1.20: incorrect custom action selection')
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
    message['AffectedObject'] = AFFECTED_OBJECT
    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        iam = sess.client('iam')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    try:
        resource = finding.details['Resources'][0]
        id_parts = resource['Id'].split(':')
        account = id_parts.pop()

        aws_support_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account}:root"
                    }
                }
            ]
        }

        role_name = 'aws_incident_support_role'

        if does_role_exist(iam, role_name):
            lowercase_str = uuid.uuid4().hex
            role_name = f'{role_name}_{lowercase_str[0:8]}'

        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(aws_support_policy),
            Description='Created by SHARR security hub remediation 1.20 rule',
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'CIS 1.20 aws support access role'
                },
            ]
        )

        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess',
        )

        message['State'] = 'RESOLVED'
        message['Note'] = '' # use default
        notify(finding, message, LOGGER, cwlogs=APPLOGGER, sns=AWS)
        return

    except Exception as e:
        LOGGER.error(e)
        failed()
        return


def does_role_exist(iam, role_name):
    """Check if the role name exists.

        Parameters
        ----------
        iam: iam client, required
        role_name: string, required

        Returns
        ------
            bool: returns if the role exists
        """
    role_exists = False

    try:
        response = iam.get_role(
            RoleName=role_name
        )

        if 'Role' in response:
            role_exists = True

    except iam.exceptions.NoSuchEntityException as e:
        role_exists = False
        LOGGER.info(e)

    return role_exists
