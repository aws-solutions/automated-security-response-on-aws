// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { NagSuppressions } from 'cdk-nag';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-nag-suppression';

export class OrgIdLookupConstruct extends Construct {
  public readonly organizationId: string;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const orgIdLookupInlineCode = `
      const {OrganizationsClient, DescribeOrganizationCommand} = require("@aws-sdk/client-organizations");
      const https = require('https');
      const url = require('url');
      
      const organizationsClient = new OrganizationsClient({});
      
      exports.handler = async function (event, context) {
        console.log('Event:', JSON.stringify(event, null, 2));
      
        let responseData = {};
        let physicalResourceId;
        let responseStatus = 'FAILED';
        let reason;
      
        try {
          if (event.RequestType === 'Create' || event.RequestType === 'Update') {
            const response = await organizationsClient.send(new DescribeOrganizationCommand({}));
            const organizationId = response.Organization?.Id;
            responseData = { OrganizationId: organizationId };
            physicalResourceId = organizationId || 'org-id-not-found';
            responseStatus = 'SUCCESS';
          } else if (event.RequestType === 'Delete') {
            // Nothing to do for delete
            physicalResourceId = event.PhysicalResourceId;
            responseStatus = 'SUCCESS';
          }
        } catch (error) {
          console.error('Error:', error);
          reason = 'Failed to retrieve Organization ID: ' + error.message;
          physicalResourceId = 'org-id-lookup-failed';
        }
      
        await sendResponse(event, context, responseStatus, responseData, physicalResourceId, reason);
      };
      
      function sendResponse(event, context, responseStatus, responseData, physicalResourceId, reason) {
        return new Promise((resolve, reject) => {
          const responseBody = JSON.stringify({
            Status: responseStatus,
            Reason: reason || 'See the details in CloudWatch Log Stream: ' + context.logStreamName,
            PhysicalResourceId: physicalResourceId,
            StackId: event.StackId,
            RequestId: event.RequestId,
            LogicalResourceId: event.LogicalResourceId,
            NoEcho: false,
            Data: responseData
          });
      
          console.log('Response body:', responseBody);
      
          const parsedUrl = url.parse(event.ResponseURL);
          const options = {
            hostname: parsedUrl.hostname,
            port: 443,
            path: parsedUrl.path,
            method: 'PUT',
            headers: {
              'content-type': '',
              'content-length': responseBody.length
            }
          };
      
          const request = https.request(options, (response) => {
            console.log('Status code:', response.statusCode);
            console.log('Status message:', response.statusMessage);
            resolve();
          });
      
          request.on('error', (error) => {
            console.log('send(..) failed executing https.request(..): ' + error);
            reject(error);
          });
      
          request.write(responseBody);
          request.end();
        });
      }
    `;

    const orgIdLookupFunction = new lambda.Function(this, 'OrgIdLookupFunction', {
      runtime: lambda.Runtime.NODEJS_20_X,
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(15),
      handler: 'index.handler',
      code: lambda.Code.fromInline(orgIdLookupInlineCode),
    });
    addCfnGuardSuppression(orgIdLookupFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(orgIdLookupFunction, 'LAMBDA_CONCURRENCY_CHECK');

    orgIdLookupFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['organizations:DescribeOrganization'],
        resources: ['*'],
      }),
    );

    if (orgIdLookupFunction.role) {
      NagSuppressions.addResourceSuppressions(
        orgIdLookupFunction.role,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason: 'AWSLambdaBasicExecutionRole is sufficiently restrictive',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason: 'Wildcard permission is required to describe Org',
          },
        ],
        true,
      );
    }

    const orgIdLookup = new cdk.CustomResource(this, 'OrgIdLookup', {
      serviceToken: orgIdLookupFunction.functionArn,
    });

    this.organizationId = orgIdLookup.getAttString('OrganizationId');
  }
}
