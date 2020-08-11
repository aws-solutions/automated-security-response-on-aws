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
#
# Imports
import re
import json
import inspect
import os
import boto3
from botocore.config import Config
from lib.metrics import Metrics

boto_config = Config(
    retries = {
        'max_attempts': 10
    }
)

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
securityhub = boto3.client('securityhub', config=boto_config, region_name=AWS_REGION)

# Classes

class InvalidFindingJson(Exception):
    pass

class Finding(object):
    """
    Security Hub Finding class
    """
    details = {} # Assuming ONE finding per event. We'll take the first.
    # finding_id = 'error'
    generator_id = 'error'
    account_id = 'error'

    def __init__(self, finding_rec):

        self.details = finding_rec
        self.generator_id = self.details.get('GeneratorId', 'error')

        if self.generator_id == 'error':
            raise InvalidFindingJson

        # Verify finding['Id']
        if not self.details.get('Id'):
            raise InvalidFindingJson

        # Account Id
        self.account_id = self.details.get('AwsAccountId', 'error')
        if self.account_id == 'error':
            raise InvalidFindingJson

    def resolve(self, message):
        """
        Update the finding_id workflow status to "RESOLVED"
        """
        self.update_text(message, status='RESOLVED')

    def flag(self, message):
        """
        Update the finding_id workflow status to "NOTIFIED" to prevent
        further CWE rules matching. Do this in playbooks after validating input
        so multiple remediations are not initiated when automatic triggers are
        in use.
        """
        self.update_text(message, status='NOTIFIED')

    def update_text(self, message, status=None):
        """
        Update the finding_id text
        """

        workflow_status = {}
        if status:
            workflow_status = { 'Workflow': { 'Status': status } }

        try:
            securityhub.batch_update_findings(
                FindingIdentifiers=[
                    {
                        'Id': self.details.get('Id'),
                        'ProductArn': self.details.get('ProductArn')
                    }
                ],
                Note={
                    'Text': message,
                    'UpdatedBy': inspect.stack()[0][3]
                },
                **workflow_status
            )

        except Exception as e:
            print(e)
            raise

    def is_cis_ruleset(self):
        """
        Returns false or a decomposition of the GeneratorId specific to the
        AWS CIS Foundations Benchmark ruleset
        """

        # GeneratorId identifies the specific compliance matched. Examples:
        # arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/1.3
        genid_regex = re.search(
            '^arn:.*?:ruleset/cis-aws-foundations-benchmark/v/(?P<version>.*?)/rule/(?P<rule>.*?)$',
            self.generator_id)

        if not genid_regex:
            return False

        return {
            'ruleset': 'cis-aws-foundations-benchmark',
            'version': genid_regex.group('version'),
            'ruleid': genid_regex.group('rule')
        }

    def is_aws_fsbp_ruleset(self):
        """
        Returns false or a decomposition of the GeneratorId specific to the
        AWS Foundational Security Best Practices ruleset
        """

        # Generator Id example:
        # aws-foundational-security-best-practices/v/1.0.0/CloudTrail.1
        genid_regex = re.search(
            '^aws-foundational-security-best-practices/v/(?P<version>.*?)/(?P<rule>.*?)$',
            self.generator_id)

        if not genid_regex:
            return False

        return {
            'ruleset': 'aws-foundational-security-best-practices',
            'version': genid_regex.group('version'),
            'ruleid': genid_regex.group('rule')
        }

#================
# Utilities
#================
def notify(finding, message, logger, cwlogs=False, sechub=True, sns=False):
    """
    Consolidates several outputs to a single call.

    Attributes
    ----------
    finding: finding object for which notification is to be done
    message: dict of notification data:
        {
            'Account': string,
            'AffectedOject': string,
            'Remediation': string,
            'State': string,
            'Note': string
        }
    logger: logger object for logging to stdout
    cwlogs: boolean - log to application log group?
    sechub: boolean - update Security Hub notes on the finding?
    sns: boolean - send to sns topic?
    """

    remediation_adj = ''
    if 'State' in message:
        if message['State'] == 'RESOLVED':
            remediation_adj = 'remediation was successful'
        elif message['State'] == 'INITIAL':
            remediation_adj = 'remediation started'
        elif message['State'] == 'FAILED':
            remediation_adj = 'remediation failed. Please remediate manually'
        if 'Note' not in message or not message['Note']:
            message['Note'] = '"' + message.get('Remediation', 'error missing remediation') +\
            '" ' + remediation_adj
    else:
        message['State'] = 'INFO'

    if 'Note' not in message or not message['Note']:
        message['Note'] = 'error - missing note'

    #send metrics
    try:
        metrics_data = message['metrics_data']
        metrics = Metrics({'detail-type': 'None'})
        metrics_data['status'] = message['State']
        metrics.send_metrics(metrics_data)
    except Exception as e:
        logger.error(e)
        logger.error('Failed to send metrics')

    # lambda logs - always
    logger.info(
        message.get('State', 'INFO') + ': ' + message.get('Note') +\
        ', Account Id: ' + message.get('Account', 'error') + \
        ', Resource: ' + message.get('AffectedObject', 'error')
    )

    # log to application log
    if cwlogs:
        # to take advantage of buffering, the caller controls the
        # connection.
        cwlogs.add_message(
            message.get('State') + ': ' + message.get('Note') +\
            ', Account Id: ' + message.get('Account', 'error') + \
            ', Resource: ' + message.get('AffectedObject', 'error')
        )

    if sechub:
        if message.get('State') == 'RESOLVED':
            finding.resolve(message.get('State') + ': ' + message.get('Note'))
        elif message.get('State') == 'INITIAL':
            finding.flag(message.get('State') + ': ' + message.get('Note'))
        else:
            finding.update_text(message.get('State', 'INFO') + ': ' + message.get('Note'))

    if sns:
        try:
            sns.postit('SO0111-SHARR_Topic', message, AWS_REGION)
        except Exception as e:
            logger.error(e)
            logger.error('Unable to send to sns')
