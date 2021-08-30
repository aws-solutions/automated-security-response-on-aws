#!/usr/bin/python
###############################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.         #
#                                                                             #
#  Licensed under the Apache License Version 2.0 (the "License"). You may not #
#  use this file except in compliance with the License. A copy of the License #
#  is located at                                                              #
#                                                                             #
#      http://www.apache.org/licenses/LICENSE-2.0/                            #
#                                                                             #
#  or in the "license" file accompanying this file. This file is distributed  #
#  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express #
#  or implied. See the License for the specific language governing permis-    #
#  sions and limitations under the License.                                   #
###############################################################################
 
def process_results(event, context):
    print(f'Created encrypted SNS topic {event["sns_topic_arn"]}')
    print(f'Created encrypted Config bucket {event["config_bucket"]}')
    print(f'Created access logging for Config bucket in bucket {event["logging_bucket"]}')
    print('Enabled AWS Config by creating a default recorder')
    return {
        "response": {
            "message": "AWS Config successfully enabled",
            "status": "Success"
        }
    }