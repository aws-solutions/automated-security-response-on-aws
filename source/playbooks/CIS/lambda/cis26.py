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

import os
import hashlib
from botocore.config import Config
import botocore
from lib.sechub_findings import Finding, notify
from lib.logger import Logger
from lib.awsapi_helpers import AWSClient, BotoSession
from lib.applogger import LogHandler
from lib.metrics import Metrics

#------------------------------
# Remediation-Specific
#------------------------------
LAMBDA_ROLE = 'SO0111_CIS26_memberRole'
REMEDIATION = 'Enable Access Logging on CloudTrail logs bucket'
AFFECTED_OBJECT = 'CloudTrail'
LOGGING_BUCKET_PREFIX = 'so0111-sharr-cloudtrailaccessLogs'
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
        LOGGER.debug('CIS 2.6: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 2.6: incorrect custom action selection.')
        return

    if (cis_data['ruleid'] not in ['2.6']):
        # Not an applicable finding - does not match rule
        # send an error and exit
        LOGGER.debug('CIS 2.6: incorrect custom action selection.')
        APPLOGGER.add_message('CIS 2.6: incorrect custom action selection.')
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
    #==========================================================================
    # Parse ARN of non-compliant resource from Security Hub CWE
    try:
        ctBucket = str(finding.details['Resources'][0]['Id'])
        # Remove ARN string, create new variable
        formattedCTBucket = ctBucket.replace("arn:aws:s3:::", "")
    except Exception as e:
        message['Note'] = str(e) + ' - Finding format is not as expected.'
        message['State'] = 'FAILED'
        notify(finding, message, LOGGER, cwlogs=APPLOGGER)
        return

    message['AffectedObject'] = AFFECTED_OBJECT + ': ' + formattedCTBucket

    try:
        sess = BotoSession(finding.account_id, LAMBDA_ROLE)
        ssm = sess.client('ssm')
        s3 = sess.client('s3')
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # Mark the finding NOTIFIED while we remediate
    message['State'] = 'INITIAL'
    notify(finding, message, LOGGER, cwlogs=APPLOGGER)

    # Create a bucket for the access logs
    # The same bucket is used to log access for all CloudTrails in the same account
    accessLoggingBucket = LOGGING_BUCKET_PREFIX + "-" + finding.account_id
    accessLoggingBucket = accessLoggingBucket.lower()

    try:
        kwargs = {
            'Bucket': accessLoggingBucket,
            'GrantWrite': 'uri=http://acs.amazonaws.com/groups/s3/LogDelivery',
            'GrantReadACP': 'uri=http://acs.amazonaws.com/groups/s3/LogDelivery'
        }
        if AWS_REGION != 'us-east-1':
            kwargs['CreateBucketConfiguration'] = {
                'LocationConstraint': AWS_REGION
            }

        s3.create_bucket(**kwargs)

        s3.put_bucket_encryption(
            Bucket=accessLoggingBucket,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] == 'BucketAlreadyExists':
            pass
        else:
            LOGGER.error(error)
            failed()
            return
    except Exception as e:
        LOGGER.error(e)
        failed()
        return

    # execute automation with ConfigureS3BucketLogging Document
    try:
        response = ssm.start_automation_execution(
            DocumentName='AWS-ConfigureS3BucketLogging',
            DocumentVersion='1',
            Parameters={
                'BucketName': [formattedCTBucket],
                'GrantedPermission': ['READ'],
                'GranteeType': ['Group'],
                'GranteeUri': ['http://acs.amazonaws.com/groups/s3/LogDelivery'], ## Must Use URI, fails with Canonical Group Id
                'TargetPrefix' : [formattedCTBucket + '/'],
                'TargetBucket': [accessLoggingBucket],
                'AutomationAssumeRole': ['arn:aws:iam::' + finding.account_id + ':role/' + LAMBDA_ROLE]
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
