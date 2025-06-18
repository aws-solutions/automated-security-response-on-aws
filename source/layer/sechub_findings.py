# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import inspect
import json
import os
from typing import Any, Union

from botocore.exceptions import ClientError
from layer.awsapi_cached_client import AWSCachedClient
from layer.utils import publish_to_sns

# Get AWS region from Lambda environment. If not present then we're not
# running under lambda, so defaulting to us-east-1
securityhub = None


def get_securityhub():
    global securityhub
    if securityhub is None:
        securityhub = AWSCachedClient(
            os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ).get_connection("securityhub")
    return securityhub


UNHANDLED_CLIENT_ERROR = "An unhandled client error occurred: "

# Local functions


def get_ssm_connection(apiclient):
    # returns a client id for ssm in the region of the finding via apiclient
    return apiclient.get_connection("ssm")


# Classes


class InvalidFindingJson(Exception):
    pass


class Finding(object):
    """
    Security Hub Finding class
    """

    details: Any = {}  # Assuming ONE finding per event. We'll take the first.
    generator_id = "error"
    account_id = "error"
    resource_region = "error"
    standard_name = ""
    standard_shortname = "error"
    standard_version = "error"
    standard_control = "error"
    remediation_control = ""
    standard_version_supported = "False"
    title = ""
    description = ""
    region = None
    arn = ""
    uuid = ""

    def __init__(self, finding_rec):
        self.region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.aws_api_client = AWSCachedClient(self.region)

        self.details = finding_rec
        self.arn = self.details.get("Id", "error")
        self.uuid = self.arn.split("/finding/")[1]
        self.generator_id = self.details.get("GeneratorId", "error")
        self.account_id = self.details.get("AwsAccountId", "error")
        resource = self.details.get("Resources", [])[0]
        self.resource_region = resource.get("Region", "error")

        if not self.is_valid_finding_json():
            raise InvalidFindingJson

        self.title = self.details.get("Title", "error")
        self.description = self.details.get("Description", "error")
        self.remediation_url = (
            self.details.get("Remediation", {}).get("Recommendation", {}).get("Url", "")
        )

        if (
            self.details.get("ProductFields").get("StandardsControlArn", None)
            is not None
        ):
            self._get_security_standard_fields_from_arn(
                self.details.get("ProductFields").get("StandardsControlArn")
            )
        else:
            self.standard_control = self.details.get("Compliance").get(
                "SecurityControlId"
            )
            self.standard_version = "2.0.0"
            self.standard_name = "security-control"

        self._get_security_standard_abbreviation_from_ssm()
        self._get_control_remap()
        self._set_standard_version_supported()

    def is_valid_finding_json(self):
        if self.generator_id == "error":
            return False

        # Verify finding['Id']
        if not self.details.get("Id"):
            return False

        # Account Id
        if self.account_id == "error":
            return False

        return True

    def resolve(self, message):
        """
        Update the finding_id workflow status to "RESOLVED"
        """
        self.update_text(message, status="RESOLVED")

    def flag(self, message):
        """
        Update the finding_id workflow status to "NOTIFIED" to prevent
        further CWE rules matching. Do this in playbooks after validating input
        so multiple remediations are not initiated when automatic triggers are
        in use.
        """
        self.update_text(message, status="NOTIFIED")

    def update_text(self, message, status=None):
        """
        Update the finding_id text
        """

        workflow_status = {}
        if status:
            workflow_status = {"Workflow": {"Status": status}}

        try:
            get_securityhub().batch_update_findings(
                FindingIdentifiers=[
                    {
                        "Id": self.details.get("Id"),
                        "ProductArn": self.details.get("ProductArn"),
                    }
                ],
                Note={"Text": message, "UpdatedBy": inspect.stack()[0][3]},
                **workflow_status,
            )

        except Exception as e:
            print(e)
            raise

    def _get_security_standard_fields_from_arn(self, arn):
        standards_arn_parts = arn.split(":")[5].split("/")
        self.standard_name = standards_arn_parts[1]
        self.standard_version = standards_arn_parts[3]
        self.standard_control = standards_arn_parts[4]

    def _get_control_remap(self):
        self.remediation_control = self.standard_control  # Defaults to self
        try:
            local_ssm = get_ssm_connection(self.aws_api_client)
            remap = (
                local_ssm.get_parameter(
                    Name=f"/Solutions/SO0111/{self.standard_shortname}/{self.standard_version}/{self.standard_control}/remap"
                )
                .get("Parameter")
                .get("Value")
            )
            self.remediation_control = remap

        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type in "ParameterNotFound":
                return
            else:
                print(UNHANDLED_CLIENT_ERROR + exception_type)
                return

        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _get_security_standard_abbreviation_from_ssm(self):
        try:
            local_ssm = get_ssm_connection(self.aws_api_client)
            abbreviation = (
                local_ssm.get_parameter(
                    Name=f"/Solutions/SO0111/{self.standard_name}/{self.standard_version}/shortname"
                )
                .get("Parameter")
                .get("Value")
            )
            self.standard_shortname = abbreviation

        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type in "ParameterNotFound":
                self.security_standard = "notfound"
            else:
                print(UNHANDLED_CLIENT_ERROR + exception_type)
                return

        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            return

    def _set_standard_version_supported(self):
        try:
            local_ssm = get_ssm_connection(self.aws_api_client)

            version_status = (
                local_ssm.get_parameter(
                    Name=f"/Solutions/SO0111/{self.standard_name}/{self.standard_version}/status"
                )
                .get("Parameter")
                .get("Value")
            )

            if version_status == "enabled":
                self.standard_version_supported = "True"
            else:
                self.standard_version_supported = "False"

        except ClientError as ex:
            exception_type = ex.response["Error"]["Code"]
            if exception_type in "ParameterNotFound":
                self.standard_version_supported = "False"
            else:
                print(UNHANDLED_CLIENT_ERROR + exception_type)
                self.standard_version_supported = "False"

        except Exception as e:
            print(UNHANDLED_CLIENT_ERROR + str(e))
            self.standard_version_supported = "False"


# ================
# Utilities
# ================
class InvalidValue(Exception):
    pass


class SHARRNotification(object):
    # These are private - they cannot be changed after the object is created
    __security_standard = ""
    __controlid = None
    __region = ""

    severity = "INFO"
    message = ""
    remediation_output = ""
    remediation_status = ""
    remediation_account_alias = ""
    finding_link = ""
    ticket_url = ""
    logdata: Any = []
    send_to_sns = False
    finding_info: Union[dict[str, Any], str] = {}

    def __init__(self, security_standard, region, controlid=None):
        """
        Initialize the class
        applogger_name determines the log stream name in CW Logs
        ex. SHARRNotification(<string>, 'us-east-1', None) -> logs to <string>-2021-01-22
        ex. SHARRNotification('FSBP', 'us-east-1', 'EC2.1') -> logs to FSBP-EC2.1-2021-01-22
        """
        self.__security_standard = security_standard
        self.__region = region
        if controlid:
            self.__controlid = controlid
        self.applogger = self._get_log_handler()

    def _get_log_handler(self):
        """
        Create a loghandler object
        """
        from layer.applogger import LogHandler

        applogger_name = self.__security_standard
        if self.__controlid:
            applogger_name += "-" + self.__controlid

        applogger = LogHandler(applogger_name)
        return applogger

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def notify(self):
        """
        Send notifications to the application CW Logs stream and sns
        """
        sns_notify_json = {
            "Remediation_Status": self.remediation_status,
            "Severity": self.severity,
            "Account_Alias": self.remediation_account_alias,
            "Remediation_Output": self.remediation_output,
            "Message": self.message,
            "Finding_Link": self.finding_link,
            "Finding": self.finding_info,
        }

        if self.ticket_url:
            sns_notify_json["Ticket_URL"] = self.ticket_url

        if self.send_to_sns:
            sent_id = publish_to_sns(
                "SO0111-SHARR_Topic",
                json.dumps(sns_notify_json, indent=2, default=str),
                self.__region,
            )
            print(f"Notification message ID {sent_id} sent.")
        self.applogger.add_message(self.severity + ": " + self.message)
        if self.logdata:
            for line in self.logdata:
                self.applogger.add_message(line)
        self.applogger.flush()
