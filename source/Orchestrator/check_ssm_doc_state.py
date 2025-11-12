# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError
from layer import utils
from layer.awsapi_cached_client import BotoSession
from layer.cloudwatch_metrics import CloudWatchMetrics
from layer.powertools_logger import get_logger
from layer.sechub_findings import Finding
from layer.tracer_utils import init_tracer

ORCH_ROLE_NAME = "SO0111-ASR-Orchestrator-Member"  # role to use for cross-account

logger = get_logger("check_ssm_doc_state")
tracer = init_tracer()

session = boto3.session.Session()
AWS_REGION = session.region_name


def _get_ssm_client(account, role, region=""):
    """
    Create a client for ssm
    """
    kwargs = {}
    if region:
        kwargs["region_name"] = region

    return BotoSession(account, f"{role}").client("ssm", **kwargs)


def _add_doc_state_to_answer(doc: str, account: str, region: str, answer: Any) -> None:
    try:
        # Connect to APIs
        ssm = _get_ssm_client(account, ORCH_ROLE_NAME, region)

        # Validate input
        docinfo = ssm.describe_document(Name=doc)["Document"]

        doctype = docinfo.get("DocumentType", "unknown")

        if doctype != "Automation":
            answer.update(
                {
                    "status": "ERROR",
                    "message": 'Document Type is not "Automation": ' + str(doctype),
                }
            )
            logger.error(answer.message)

        docstate = docinfo.get("Status", "unknown")
        if docstate != "Active":
            answer.update(
                {
                    "status": "NOTACTIVE",
                    "message": 'Document Status is not "Active": ' + str(docstate),
                }
            )
            logger.error(answer.message)

        answer.update({"status": "ACTIVE"})

    except ClientError as ex:
        exception_type = ex.response["Error"]["Code"]
        if exception_type in "InvalidDocument":
            answer.update(
                {"status": "NOTFOUND", "message": f"Document {doc} does not exist."}
            )
            logger.error(answer.message)
        elif exception_type == "AccessDenied":
            answer.update(
                {
                    "status": "ACCESSDENIED",
                    "message": f"Could not assume role for {doc} in {account} in {region}",
                }
            )
            logger.error(answer.message)
            try:
                cloudwatch_metrics = CloudWatchMetrics()
                cloudwatch_metric = {
                    "MetricName": "AssumeRoleFailure",
                    "Unit": "Count",
                    "Value": 1,
                }
                cloudwatch_metrics.send_metric(cloudwatch_metric)
            except Exception:
                logger.debug("Did not send Cloudwatch metric")
        elif exception_type == "ThrottlingException":
            # Re-raise throttling exceptions so Step Functions can retry with backoff
            logger.warning(f"SSM API throttled for document {doc}, will retry")
            raise
        else:
            answer.update(
                {
                    "status": "CLIENTERROR",
                    "message": "An unhandled client error occurred: " + exception_type,
                }
            )
            logger.error(answer.message)

    except Exception as e:
        answer.update(
            {"status": "ERROR", "message": "An unhandled error occurred: " + str(e)}
        )
        logger.error(answer.message)


@tracer.capture_lambda_handler  # type: ignore[misc]
def lambda_handler(event: Dict[str, Any], _: Any) -> Dict[str, Any]:
    answer = utils.StepFunctionLambdaAnswer()
    logger.info("Processing SSM doc state check", **event)
    if "Finding" not in event or "EventType" not in event:
        answer.update(
            {"status": "ERROR", "message": "Missing required data in request"}
        )
        logger.error(answer.message)
        return answer.json()  # type: ignore[no-any-return]

    product_name = (
        event["Finding"]
        .get("ProductFields", {})
        .get("aws/securityhub/ProductName", "Security Hub")
    )

    if product_name != "Security Hub":
        workflow_doc = event.get("Workflow", {})
        non_sec_hub_finding = event["Finding"]
        non_sec_hub_resources = non_sec_hub_finding.get("Resources", [])
        resource_region = AWS_REGION
        if len(non_sec_hub_resources) >= 1:
            resource_region = non_sec_hub_resources[0].get("Region", "")
        answer.update(
            {
                "securitystandard": "N/A",
                "securitystandardversion": "N/A",
                "controlid": "N/A",
                "playbookenabled": "N/A",
                "accountid": non_sec_hub_finding["AwsAccountId"],
                "resourceregion": resource_region,
                "automationdocid": workflow_doc["WorkflowDocument"],
                "remediationrole": (
                    workflow_doc["WorkflowRole"]
                    if workflow_doc["WorkflowRole"] != ""
                    else "SO0111-UseDefaultRole"
                ),
            }
        )
        answer.update({"status": "ACTIVE"})
        return answer.json()  # type: ignore[no-any-return]

    finding = Finding(event["Finding"])

    answer.update(
        {
            "securitystandard": (
                finding.standard_shortname
                if finding.standard_shortname != "error"
                else finding.standard_name
            ),
            "securitystandardversion": finding.standard_version,
            "controlid": finding.standard_control,
            "playbookenabled": finding.playbook_enabled,
            "accountid": finding.account_id,
            "resourceregion": finding.resource_region,
            "remediationrole": "",
            "automationdocid": "",
        }
    )

    if finding.playbook_enabled != "True":
        answer.update(
            {
                "status": "NOTENABLED",
                "message": f'Security Standard is not enabled": "{finding.standard_name} version {finding.standard_version}"',
            }
        )
        return answer.json()  # type: ignore[no-any-return]

    # Is there alt workflow configuration?
    alt_workflow_doc = event.get("Workflow", {}).get("WorkflowDocument", None)

    automation_docid = f"ASR-{finding.standard_shortname}_{finding.standard_version}_{finding.remediation_control}"
    remediation_role = f"SO0111-Remediate-{finding.standard_shortname}-{finding.standard_version}-{finding.remediation_control}"

    answer.update(
        {"automationdocid": automation_docid, "remediationrole": remediation_role}
    )

    # If alt workflow is configured we don't need to check doc state, as we checked
    # it in get_approval_requirement
    if alt_workflow_doc:
        answer.update({"status": "ACTIVE"})
    else:
        _add_doc_state_to_answer(
            automation_docid, finding.account_id, finding.resource_region, answer
        )

    return answer.json()  # type: ignore[no-any-return]
