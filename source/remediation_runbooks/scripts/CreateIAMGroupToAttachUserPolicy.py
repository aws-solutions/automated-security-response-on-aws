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
import boto3

boto_config = Config(
    retries ={
        'mode': 'standard'
    }
)

responses = {}
responses["CreateIAMGroupToAttachUserPolicyResponse"] = []

def connect_to_iam(boto_config):
    return boto3.client('iam', config=boto_config)

def create_iam_group_to_attach_user_policy(event, context):
    try:
        iam = connect_to_iam(boto_config)
        aws_iam_user = event['Details']['AwsIamUser']
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

        response = iam.add_user_to_group(
            GroupName=group_name,
            UserName=username
        )

        responses["CreateIAMGroupToAttachUserPolicyResponse"].append({
            "AwsIamUser" : aws_iam_user,
            "Response" : response
        })

        return {
            "output": "IAM Group creation is successful.",
            "http_responses": responses
        }

    except Exception as e:
        print(e)
        return {
            "output": "IAM Group creation is unsuccessful.",
            "http_responses": responses
        }


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
        print(e)

    return group_exists