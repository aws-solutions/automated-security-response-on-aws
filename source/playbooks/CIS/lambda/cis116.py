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

# ------------------------------
# Remediation-Specific
# ------------------------------
LAMBDA_ROLE = 'SO0111_CIS116_memberRole'
REMEDIATION = 'Ensure IAM policies are attached only to groups or roles'
AFFECTED_OBJECT = 'IAM User'
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
    LOGGER.info(event)
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
        LOGGER.debug('CIS 1.16: incorrect custom action selection')
        APPLOGGER.add_message('CIS 1.16: incorrect custom action selection')
        return

    if (cis_data['ruleid'] not in ['1.16']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 1.16: incorrect custom action selection')
        APPLOGGER.add_message('CIS 1.16: incorrect custom action selection')
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

    # ==========================================================================
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
        details = finding.details['Resources'][0]['Details']

        aws_iam_user = details['AwsIamUser']
        managed_policies = aws_iam_user['AttachedManagedPolicies'] if 'AttachedManagedPolicies' in aws_iam_user else []
        username = aws_iam_user['UserName']
        user_groups = aws_iam_user['GroupList'] if 'GroupList' in aws_iam_user else []
        inline_policies = aws_iam_user['UserPolicyList'] if 'UserPolicyList' in aws_iam_user else []

        group_name = f'{username}'

        if user_groups:
            group_name = user_groups[0]
        else:
            if does_group_exist(iam, group_name):
                lowercase_str = uuid.uuid4().hex
                group_name = f'{group_name}_{lowercase_str[0:8]}'

            iam.create_group(
                GroupName=group_name
            )

        if inline_policies:
            for policy in inline_policies:
                current_policy_name = policy['PolicyName']

                policy_details = iam.get_user_policy(
                    UserName=username,
                    PolicyName=current_policy_name
                )

                new_policy_name = f'{current_policy_name}-sharr-cis116'

                create_policy_response = iam.create_policy(
                    PolicyName=new_policy_name,
                    PolicyDocument=json.dumps(policy_details['PolicyDocument'])
                )

                policy_arn = create_policy_response['Policy']['Arn']

                attach_policy_response = iam.attach_group_policy(
                    GroupName=group_name,
                    PolicyArn=policy_arn
                )

                if attach_policy_response['ResponseMetadata'] and \
                        attach_policy_response['ResponseMetadata']['HTTPStatusCode'] and \
                        attach_policy_response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    iam.delete_user_policy(
                        UserName=username,
                        PolicyName=current_policy_name
                    )

        if managed_policies:
            for managed_policy in managed_policies:
                policy_arn = managed_policy['PolicyArn']

                attach_policy_response = iam.attach_group_policy(
                    GroupName=group_name,
                    PolicyArn=policy_arn
                )

                if attach_policy_response['ResponseMetadata'] and \
                        attach_policy_response['ResponseMetadata']['HTTPStatusCode'] and \
                        attach_policy_response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    iam.detach_user_policy(
                        UserName=username,
                        PolicyArn=policy_arn
                    )

        iam.add_user_to_group(
            GroupName=group_name,
            UserName=username
        )

        message['State'] = 'RESOLVED'
        message['Note'] = ''  # use default
        notify(finding, message, LOGGER, cwlogs=APPLOGGER, sns=AWS)
        return

    except Exception as e:
        LOGGER.error(e)
        failed()
        return


def does_group_exist(iam, group_name):
    """Check if the group name exists.

        Parameters
        ----------
        iam: iam client, required
        group_name: string, required

        Returns
        ------
            bool: returns if the group exists
        """
    group_exists = False

    try:
        response = iam.get_group(
            GroupName=group_name
        )

        if 'Group' in response:
            group_exists = True

    except iam.exceptions.NoSuchEntityException as e:
        group_exists = False
        LOGGER.info(e)

    return group_exists
