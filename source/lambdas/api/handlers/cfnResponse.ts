// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as https from 'https';
import * as url from 'url';
import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';

export const SUCCESS = 'SUCCESS';
export const FAILED = 'FAILED';

// copied from https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
// and converted from JS to TS
export function send(
  event: CloudFormationCustomResourceEvent,
  context: Context,
  responseStatus: typeof SUCCESS | typeof FAILED,
  responseData: Record<string, any>,
  physicalResourceId?: string,
  noEcho?: boolean,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const responseBody = JSON.stringify({
      Status: responseStatus,
      Reason: 'See the details in CloudWatch Log Stream: ' + context.logStreamName,
      PhysicalResourceId: physicalResourceId || context.logStreamName,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      NoEcho: noEcho || false,
      Data: responseData,
    });

    console.log('Response body:\n', responseBody);

    const parsedUrl = url.parse(event.ResponseURL);
    const options: https.RequestOptions = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: parsedUrl.path,
      method: 'PUT',
      headers: {
        'content-type': '',
        'content-length': responseBody.length,
      },
    };

    const request = https.request(options, (response) => {
      console.log('Status code: ' + response.statusCode);
      resolve(context.done());
    });

    request.on('error', (error) => {
      console.log('send(..) failed executing https.request(..): ' + maskCredentialsAndSignature(error.message));
      reject(context.done(error));
    });

    request.write(responseBody);
    request.end();
  });
}

function maskCredentialsAndSignature(message: string): string {
  return message
    .replace(/X-Amz-Credential=[^&\s]+/i, 'X-Amz-Credential=*****')
    .replace(/X-Amz-Signature=[^&\s]+/i, 'X-Amz-Signature=*****');
}
