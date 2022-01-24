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
responses["DeattachIAMPolicyFromUsersResponse"] = []

def connect_to_iam(boto_config):
    return boto3.client('iam', config=boto_config)

def deattach_iam_policy_from_users(event, context):
    try:
        iam = connect_to_iam(boto_config)
        resource_id = event['Id']

        response = iam.get_policy(
            PolicyArn=resource_id
        )

        print('Inline policy >>>>>>>>>>>>>>>')
        print(response)

        entity_response = iam.list_entities_for_policy(
            PolicyArn=resource_id,
            EntityFilter='User'
        )

        print(entity_response)

        policy_users = entity_response['PolicyUsers']

        for policy_user in policy_users:
            response = iam.detach_user_policy(
                UserName=policy_user['UserName'],
                PolicyArn=resource_id
            )
            responses["DeattachIAMPolicyFromUsersResponse"].append({
                "Id" : resource_id,
                "UserName" : policy_user['UserName'],
                "Response" : response
            })

        return {
            "output": "IAM policy removal is successful.",
            "http_responses": responses
        }

    except Exception as e:
        print(e)
        return {
            "output": "IAM policy removal is unsuccessful.",
            "http_responses": responses
        }