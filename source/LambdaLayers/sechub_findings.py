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
#
# Imports
import re
import json
import inspect
import os
import boto3
from botocore.config import Config
from utils import publish_to_sns

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
class InvalidValue(Exception):
    pass

class SHARRNotification(object):
    # These are private - they cannot be changed after the object is created
    __security_standard = ''
    __control_id =''
    __notification_type = ''
    __applogger = ''

    severity = 'INFO'
    message = ''
    logdata = []
    send_to_sns = False

    def __init__(self, security_standard, controlid=None, notification_type='ORCHESTRATOR'):
        """
        Initialize the class
        applogger_name determines the log stream name in CW Logs. Use
        notification_type='SHARR' and security_standard='APP' for app-level logs
        For orchestrator, specify security_standard='APP' for general log, otherwise
        specify security_standard and controlid

        ex. SHARRNotification('APP', None, 'SHARR') -> logs to SHARR-APP-2021-01-22
        ex. SHARRNotification('APP') -> logs to ORCHESTRATOR-APP-2021-01-22
        ex. SHARRNotification('AFSBP') -> logs to ORCHESTRATOR-AFSBP-2021-01-22
        ex. SHARRNotification('AFSBP','EC2.1') -> logs to ORCHESTRATOR-AFSBP-EC2.1-2021-01-22
        """
        from applogger import LogHandler

        self.__security_standard = security_standard
        self.__notification_type = notification_type
        applogger_name = self.__notification_type + '-' + self.__security_standard
        if controlid:
            self.__controlid = controlid
            applogger_name += '-' + controlid

        self.applogger = LogHandler(applogger_name)

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def notify(self):
        """
        Send notifications to the application CW Logs stream and sns
        """

        if self.send_to_sns:
            publish_to_sns('SO0111-SHARR_Topic', self.severity + ':' + self.message, AWS_REGION)

        self.applogger.add_message(
            self.severity + ': ' + self.message
        )
        if self.logdata:
            for line in self.logdata:
                self.applogger.add_message(
                    line
                )
        self.applogger.flush()
