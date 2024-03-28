# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import boto3
from botocore.config import Config

boto_config = Config(retries={"mode": "standard", "max_attempts": 10})

endpointTypes = ["HTTP", "Firehose", "Lambda", "Application", "SQS"]


def connect_to_sns():
    return boto3.client("sns", config=boto_config)


def lambda_handler(event, _):
    """
    Enable delivery status logging on a SNS topic

    `event` should have the following keys and values:
    `logging_role`: the ARN of the IAM Role used to log successful and failed deliveries
    `topic_arn`: the arn of the SNS Topic to enable delivery status logging on

    `context` is ignored
    """

    logging_role = event["logging_role"]
    topic_arn = event["topic_arn"]
    sample_rate = event["sample_rate"]

    add_roles_to_topic(logging_role, topic_arn)
    add_sample_rate_to_topic(topic_arn, sample_rate)

    topic_attributes = get_topic_attributes(topic_arn)

    return {
        "HTTPFailureFeedbackRoleArn": topic_attributes["Attributes"][
            "HTTPFailureFeedbackRoleArn"
        ],
        "HTTPSuccessFeedbackRoleArn": topic_attributes["Attributes"][
            "HTTPSuccessFeedbackRoleArn"
        ],
        "HTTPSuccessFeedbackSampleRate": topic_attributes["Attributes"][
            "HTTPSuccessFeedbackSampleRate"
        ],
        "FirehoseFailureFeedbackRoleArn": topic_attributes["Attributes"][
            "FirehoseFailureFeedbackRoleArn"
        ],
        "FirehoseSuccessFeedbackRoleArn": topic_attributes["Attributes"][
            "FirehoseSuccessFeedbackRoleArn"
        ],
        "FirehoseSuccessFeedbackSampleRate": topic_attributes["Attributes"][
            "FirehoseSuccessFeedbackSampleRate"
        ],
        "LambdaFailureFeedbackRoleArn": topic_attributes["Attributes"][
            "LambdaFailureFeedbackRoleArn"
        ],
        "LambdaSuccessFeedbackRoleArn": topic_attributes["Attributes"][
            "LambdaSuccessFeedbackRoleArn"
        ],
        "LambdaSuccessFeedbackSampleRate": topic_attributes["Attributes"][
            "LambdaSuccessFeedbackSampleRate"
        ],
        "ApplicationFailureFeedbackRoleArn": topic_attributes["Attributes"][
            "ApplicationFailureFeedbackRoleArn"
        ],
        "ApplicationSuccessFeedbackRoleArn": topic_attributes["Attributes"][
            "ApplicationSuccessFeedbackRoleArn"
        ],
        "ApplicationSuccessFeedbackSampleRate": topic_attributes["Attributes"][
            "ApplicationSuccessFeedbackSampleRate"
        ],
        "SQSFailureFeedbackRoleArn": topic_attributes["Attributes"][
            "SQSFailureFeedbackRoleArn"
        ],
        "SQSSuccessFeedbackRoleArn": topic_attributes["Attributes"][
            "SQSSuccessFeedbackRoleArn"
        ],
        "SQSSuccessFeedbackSampleRate": topic_attributes["Attributes"][
            "SQSSuccessFeedbackSampleRate"
        ],
    }


def add_roles_to_topic(logging_role, topic_arn):
    """
    Configures the IAM role `logging_role` that will log successful and failed deliveries to SNS Topic `topic_arn`
    """
    sns = connect_to_sns()
    try:
        for endpoint in endpointTypes:
            sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName=f"{endpoint}SuccessFeedbackRoleArn",
                AttributeValue=logging_role,
            )
            sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName=f"{endpoint}FailureFeedbackRoleArn",
                AttributeValue=logging_role,
            )

    except Exception as e:
        reset_to_recognized_state(topic_arn)
        exit(f"Failed to set success/failure role of topic {topic_arn}: {str(e)}")


def add_sample_rate_to_topic(topic_arn, sample_rate):
    """
    Configures the Success sample rate, the percentage of successful messages for which you want to receive CloudWatch Logs.
    """
    sns = connect_to_sns()
    try:
        for endpoint in endpointTypes:
            sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName=f"{endpoint}SuccessFeedbackSampleRate",
                AttributeValue=sample_rate,
            )

    except Exception as e:
        reset_to_recognized_state(topic_arn)
        exit(f"Failed to set success sample rate of SNS topic {topic_arn}: {str(e)}")


def get_topic_attributes(topic_arn):
    """
    Grabs Topic Attributes to verify topic values were set as expected.
    """
    sns = connect_to_sns()
    try:
        topic_attributes = sns.get_topic_attributes(TopicArn=topic_arn)
        return topic_attributes

    except Exception as e:
        exit(f"Failed to get attributes of SNS topic {topic_arn}: {str(e)}")


def reset_to_recognized_state(topic_arn):
    """
    Used in case of error, will unset all delivery status logging parameters.
    """
    sns = connect_to_sns()
    for endpoint in endpointTypes:
        try:
            sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName=f"{endpoint}SuccessFeedbackRoleArn",
                AttributeValue="",
            )
            sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName=f"{endpoint}FailureFeedbackRoleArn",
                AttributeValue="",
            )
        except Exception:
            print(
                f"There was an error while resetting SNS Topic {topic_arn}, please manually turn off delivery status logging for protocol {endpoint}"
            )
