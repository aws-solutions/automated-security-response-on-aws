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
import json
from botocore.config import Config
from lib.sechub_findings import Finding, notify
from lib.logger import Logger
from lib.awsapi_helpers import AWSClient, BotoSession
from lib.applogger import LogHandler
from lib.metrics import Metrics

# ------------------------------
# Remediation-Specific
# ------------------------------
LAMBDA_ROLE = 'SO0111_CIS27_memberRole'  # role to use for cross-account
REMEDIATION = 'Encrypt CloudTrail logs at rest using AWS KMS CMKs'
AFFECTED_OBJECT = 'CloudTrail'
# ------------------------------

# initialise loggers
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
APPLOGGER = LogHandler(os.path.basename(__file__[:-3]))  # application logger for CW Logs

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
        LOGGER.debug('CIS 2.7: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 2.7: incorrect custom action selection.')
        return

    if (cis_data['ruleid'] not in ['2.7']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 2.7: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 2.7: incorrect custom action selection.')
        return

    resource_type = str(finding.details['Resources'][0]["Type"])

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

    # ==========================================================================
    # parse non-compliant trail from Security Hub finding
    try:
        resource = str(finding.details['Resources'][0]['Id']).split(':')
        non_compliant_trail = resource[5].split('/')[1]
        account = resource[4]
    except KeyError as key:
        LOGGER.error('Could not find ' + str(key) + ' in Resources data for the finding')
        return
    except Exception as e:
        LOGGER.error(e)
        return

    message['AffectedObject'] = AFFECTED_OBJECT + ': ' + non_compliant_trail

    # Connect to APIs
    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        cloudtrail = sess.client('cloudtrail')
        kms = sess.client('kms')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    try:
        print(non_compliant_trail)
        print(account)

        key_policy = {
            "Version": "2012-10-17",
            "Id": "Key policy created by CloudTrail",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            f"arn:aws:iam::{account}:root",
                        ]
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow CloudTrail to encrypt logs",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "kms:GenerateDataKey*",
                    "Resource": "*",
                    "Condition": {
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{account}:trail/*"
                        }
                    }
                },
                {
                    "Sid": "Allow CloudTrail to describe key",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "kms:DescribeKey",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow principals in the account to decrypt log files",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Decrypt",
                        "kms:ReEncryptFrom"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": f"{account}"
                        },
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{account}:trail/*"
                        }
                    }
                },
                {
                    "Sid": "Allow alias creation during setup",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "kms:CreateAlias",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": "ec2.ap-southeast-2.amazonaws.com",
                            "kms:CallerAccount": f"{account}"
                        }
                    }
                },
                {
                    "Sid": "Enable cross account log decryption",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": [
                        "kms:Decrypt",
                        "kms:ReEncryptFrom"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "kms:CallerAccount": f"{account}"
                        },
                        "StringLike": {
                            "kms:EncryptionContext:aws:cloudtrail:arn": f"arn:aws:cloudtrail:*:{account}:trail/*"
                        }
                    }
                }
            ]
        }
        print(json.dumps(key_policy))

        key_response = kms.create_key(
            Policy=json.dumps(key_policy),
            Description='The key created by AWS CIS Remediation 2.7 to encrypt CloudTrail log files.',
            KeyUsage='ENCRYPT_DECRYPT',
            CustomerMasterKeySpec='SYMMETRIC_DEFAULT',
            Origin='AWS_KMS',
            BypassPolicyLockoutSafetyCheck=True
        )

        key_id = key_response['KeyMetadata']['KeyId']

        kms.create_alias(
            AliasName='alias/cloudtrail-cis-remediation',
            TargetKeyId=key_id
        )

        response = cloudtrail.update_trail(Name=non_compliant_trail, KmsKeyId=key_id)
        LOGGER.debug(response)

        message['State'] = 'RESOLVED'
        message['Note'] = ''  # use default
        notify(finding, message, LOGGER, cwlogs=APPLOGGER, sns=AWS)

    except Exception as e:
        LOGGER.error(e)
        failed()
        return
