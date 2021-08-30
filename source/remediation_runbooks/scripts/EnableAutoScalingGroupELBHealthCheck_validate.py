#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.    #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                                        #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################

import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

def connect_to_autoscaling(boto_config):
    return boto3.client('autoscaling', config=boto_config)

def verify(event, context):

    boto_config = Config(
        retries ={
          'mode': 'standard'
        }
    )
    asg_client = connect_to_autoscaling(boto_config)
    asg_name = event['AsgName']
    try:
        desc_asg = asg_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )
        if len(desc_asg['AutoScalingGroups']) < 1:
            exit(f'No AutoScaling Group found matching {asg_name}')
            
        health_check = desc_asg['AutoScalingGroups'][0]['HealthCheckType']
        print(json.dumps(desc_asg['AutoScalingGroups'][0], default=str))
        if (health_check == 'ELB'):
            return {
                "response": {
                    "message": "Autoscaling Group health check type updated to ELB",
                    "status": "Success"
                }
            }
        else:
            return {
                "response": {
                    "message": "Autoscaling Group health check type is not ELB",
                    "status": "Failed"
                }
            }
    except Exception as e:
        exit("Exception while executing remediation: " + str(e))
