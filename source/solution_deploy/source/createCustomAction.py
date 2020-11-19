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
import json
import boto3
import botocore
import hashlib
from lib.logger import Logger
import requests
from urllib.request import Request, urlopen
from datetime import datetime

# initialise logger
LOG_LEVEL = os.getenv('log_level', 'info')
LOGGER = Logger(loglevel=LOG_LEVEL)
SEND_METRICS = os.environ.get('sendAnonymousMetrics', 'No')

def send(event, context, responseStatus, responseData, physicalResourceId, LOGGER, reason=None):

    responseUrl = event['ResponseURL']
    LOGGER.debug("CFN response URL: " + responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    
    msg = 'See details in CloudWatch Log Stream: ' + context.log_stream_name
    
    LOGGER.debug('PhysicalResourceId: ' + physicalResourceId)
    if not reason:
        responseBody['Reason'] = msg
    else:
        responseBody['Reason'] = str(reason)[0:255] + '... ' + msg
        
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    
    if responseData and responseData != {} and responseData != [] and isinstance(responseData, dict):
        responseBody['Data'] = responseData

    LOGGER.debug("<<<<<<< Response body >>>>>>>>>>")
    LOGGER.debug(responseBody)
    json_responseBody = json.dumps(responseBody)

    headers = {
        'content-type': '',
        'content-length': str(len(json_responseBody))
    }

    try:
        if responseUrl == 'http://pre-signed-S3-url-for-response':
            LOGGER.info("CloudFormation returned status code: THIS IS A TEST OUTSIDE OF CLOUDFORMATION")
            pass
        else:
            response = requests.put(responseUrl,
                                    data=json_responseBody,
                                    headers=headers)
            LOGGER.info("CloudFormation returned status code: " + response.reason)
    except Exception as e:
        LOGGER.error("send(..) failed executing requests.put(..): " + str(e))
        raise

def send_metrics(data):
    try:
        if SEND_METRICS.lower() == 'yes':
            id = data['Id'][23:]
            id_as_bytes = str.encode(id)
            hash_lib = hashlib.sha256()
            hash_lib.update(id_as_bytes)
            id = hash_lib.hexdigest()
            data['Id'] = id
            usage_data = {
                'Solution': 'SO0111',
                'TimeStamp': str(datetime.utcnow().isoformat()),
                'UUID': id,
                'Data': data
            }
            url = 'https://metrics.awssolutionsbuilder.com/generic'
            req = Request( url, 
                        method = 'POST',
                        data=bytes(json.dumps(usage_data),
                        encoding='utf-8'),
                        headers = {'Content-Type': 'application/json'}
                        )
            rsp = urlopen(req)
            rspcode = rsp.getcode()
            LOGGER.debug(rspcode)
        return 
    except Exception as excep:
        print(excep)
        return 

def lambda_handler(event, context):

    responseData = {}
    physicalResourceId = ''

    try:
        properties = event['ResourceProperties']
        LOGGER.debug(json.dumps(properties))
        region = os.environ['AWS_REGION']
        partition = os.getenv('AWS_PARTITION', default='aws') # Set by deployment template
        client = boto3.client('securityhub', region_name=region)
        
        physicalResourceId = 'CustomAction' + properties.get('Id', 'ERROR')
        
        if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
            try:
                # physicalResourceId = 'createCustomAction-' + properties.get('Id', 'ERROR')
                LOGGER.info(event['RequestType'].upper() + ": " + physicalResourceId)
                response = client.create_action_target(
                    Name=properties['Name'],
                    Description=properties['Description'],
                    Id=properties['Id']
                )
                responseData['Arn'] = response['ActionTargetArn']
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'ResourceConflictException':
                    pass
                else:
                    LOGGER.error(error)
                    raise
            except Exception as e:
                metrics_data = {
                    'status': 'Failed',
                    'Id': event['StackId'],
                    'err_msg': event['RequestType']
                    }
                send_metrics(metrics_data)
                LOGGER.error(e)
                raise
        elif event['RequestType'] == 'Delete':
            try:
                # physicalResourceId = event.get('PhysicalResourceId', 'ERROR')
                LOGGER.info('DELETE: ' + physicalResourceId)
                account_id = context.invoked_function_arn.split(":")[4]
                client.delete_action_target(
                    ActionTargetArn=f"arn:{partition}:securityhub:{region}:{account_id}:action/custom/{properties['Id']}"
                )
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'ResourceNotFoundException':
                    pass
                else:
                    LOGGER.error(error)
                    raise
            except Exception as e:
                metrics_data = {
                    'status': 'Failed',
                    'Id': event['StackId'],
                    'err_msg': event['RequestType']
                    }
                send_metrics(metrics_data)
                LOGGER.error(e)
                raise
        else:
            err_msg = 'Invalid RequestType: ' + event['RequestType']
            LOGGER.error(err_msg)
            send(
                event, context,
                "FAILED",
                responseData,
                physicalResourceId,
                LOGGER,
                reason=err_msg,
            )

        send(
            event,
            context,
            "SUCCESS",
            responseData,
            physicalResourceId,
            LOGGER
        )
        metrics_data = {
            'status': 'Success',
            'Id': event['StackId']
        }
        send_metrics(metrics_data)
        return

    except Exception as err:
        LOGGER.error('An exception occurred: ')
        err_msg = err.__class__.__name__ + ': ' + str(err)
        LOGGER.error(err_msg)
        metrics_data = {
            'status': 'Failed',
            'Id': event['StackId'],
            'err_msg': 'stack installation failed.'
        }
        send_metrics(metrics_data)
        send(
            event,
            context,
            "FAILED",
            responseData,
            event.get('physicalResourceId', 'ERROR'),
            LOGGER=LOGGER,
            reason=err_msg
        )
