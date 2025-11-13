// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { CopyObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import nock from 'nock';
import { lambdaHandler, WebUIDeployer } from '../../handlers/deployWebui';

const s3Mock = mockClient(S3Client);

describe('WebUI Deploy', () => {
  const webuiSrcPath = 'solution-name/v1.2.3/webui/';
  const config = {
    SrcBucket: 'solutionBucket',
    SrcPath: webuiSrcPath,
    WebUIBucket: 'myConsoleBucket',
    awsExports: {
      AwsUserPoolsId: 'myUserPoolId',
      AwsUserPoolsWebClientId: 'myWebClient',
      AwsCognitoIdentityPoolId: 'myCognitoIdp',
      AwsAppsyncGraphqlEndpoint: 'myAppSyncEndpoint',
      AwsContentDeliveryBucket: 'myCDNBucket',
      AwsContentDeliveryUrl: 'muCDNUrl',
      AwsCognitoDomainPrefix: '',
    },
    ServiceToken: 'myServiceToken',
  };

  beforeEach(() => {
    s3Mock.reset();
    jest.clearAllMocks();
    nock.cleanAll();
    process.env.CONFIG = JSON.stringify(config);
  });

  afterEach(() => {
    delete process.env.CONFIG;
    nock.cleanAll();
  });

  describe('WebUI files are copied and config is generated', () => {
    it('should copy files and create config', async () => {
      // ARRANGE
      const webUIDeployer = new WebUIDeployer();

      const filenamesFromManifest = ['index.html', 'static/css/main.b4f55c7e.css', 'static/js/main.c838e191.js'];

      const manifestContent = JSON.stringify({ files: filenamesFromManifest });

      // Mock the manifest file read
      s3Mock
        .on(GetObjectCommand, {
          Bucket: config.SrcBucket,
          Key: webuiSrcPath + 'webui-manifest.json',
        })
        .resolves({
          Body: {
            transformToString: async () => manifestContent,
          } as any,
        });

      // Mock file copies
      for (const filename of filenamesFromManifest) {
        s3Mock
          .on(CopyObjectCommand, {
            CopySource: `${config.SrcBucket}/${webuiSrcPath}${filename}`,
            Bucket: config.WebUIBucket,
            Key: filename,
          })
          .resolves({});
      }

      // Mock config file write
      s3Mock
        .on(PutObjectCommand, {
          Bucket: config.WebUIBucket,
          Key: 'aws-exports.json',
        })
        .resolves({});

      // ACT
      await webUIDeployer.deploy();

      // ASSERT
      // Verify manifest was read
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(GetObjectCommand)[0].args[0].input).toEqual({
        Bucket: config.SrcBucket,
        Key: webuiSrcPath + 'webui-manifest.json',
      });

      // Verify files were copied
      expect(s3Mock.commandCalls(CopyObjectCommand)).toHaveLength(filenamesFromManifest.length);

      filenamesFromManifest.forEach((filename, index) => {
        expect(s3Mock.commandCalls(CopyObjectCommand)[index].args[0].input).toEqual({
          CopySource: `${config.SrcBucket}/${webuiSrcPath}${filename}`,
          Bucket: config.WebUIBucket,
          Key: filename,
        });
      });

      // Verify config file was written
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(PutObjectCommand)[0].args[0].input).toEqual({
        Bucket: config.WebUIBucket,
        Key: 'aws-exports.json',
        Body: JSON.stringify(config.awsExports),
        ContentType: 'application/json',
        Metadata: {
          'Content-Type': 'application/json',
        },
      });
    });

    it('should handle lambda Create event and send success response', async () => {
      // ARRANGE
      const responseUrl = 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/test-response-url';
      const event: CloudFormationCustomResourceEvent = {
        RequestType: 'Create',
        ResponseURL: responseUrl,
        StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345678-1234-1234-1234-123456789012',
        RequestId: 'test-request-id',
        LogicalResourceId: 'WebUIDeployment',
        ResourceType: 'Custom::WebUIDeployment',
        ServiceToken: 'myServiceToken',
        ResourceProperties: {
          ServiceToken: 'myServiceToken',
        },
      };

      const context: Context = {
        callbackWaitsForEmptyEventLoop: false,
        functionName: 'test-function',
        functionVersion: '1',
        invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
        memoryLimitInMB: '128',
        awsRequestId: 'test-aws-request-id',
        logGroupName: '/aws/lambda/test-function',
        logStreamName: '2023/01/01/[$LATEST]test-stream',
        getRemainingTimeInMillis: () => 30000,
        done: jest.fn(),
        fail: jest.fn(),
        succeed: jest.fn(),
      };

      const filenamesFromManifest = ['index.html', 'static/css/main.b4f55c7e.css', 'static/js/main.c838e191.js'];
      const manifestContent = JSON.stringify({ files: filenamesFromManifest });

      // Mock CloudFormation response
      const cfnResponseScope = nock('https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com')
        .put('/test-response-url')
        .reply(200);

      // Mock the manifest file read
      s3Mock
        .on(GetObjectCommand, {
          Bucket: config.SrcBucket,
          Key: webuiSrcPath + 'webui-manifest.json',
        })
        .resolves({
          Body: {
            transformToString: async () => manifestContent,
          } as any,
        });

      // Mock file copies
      for (const filename of filenamesFromManifest) {
        s3Mock
          .on(CopyObjectCommand, {
            CopySource: `${config.SrcBucket}/${webuiSrcPath}${filename}`,
            Bucket: config.WebUIBucket,
            Key: filename,
          })
          .resolves({});
      }

      // Mock config file write
      s3Mock
        .on(PutObjectCommand, {
          Bucket: config.WebUIBucket,
          Key: 'aws-exports.json',
        })
        .resolves({});

      // ACT
      await lambdaHandler(event, context);

      // ASSERT
      // Verify CloudFormation response was sent
      expect(cfnResponseScope.isDone()).toBe(true);

      // Verify S3 operations were performed
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(CopyObjectCommand)).toHaveLength(filenamesFromManifest.length);
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
    });

    it('should handle lambda Update event and send success response', async () => {
      // ARRANGE
      const responseUrl = 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/test-response-url';
      const event: CloudFormationCustomResourceEvent = {
        RequestType: 'Update',
        ResponseURL: responseUrl,
        StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345678-1234-1234-1234-123456789012',
        RequestId: 'test-request-id',
        LogicalResourceId: 'WebUIDeployment',
        ResourceType: 'Custom::WebUIDeployment',
        ResourceProperties: {
          ServiceToken: 'myServiceToken',
        },
        OldResourceProperties: {
          ServiceToken: 'myServiceToken',
        },
        PhysicalResourceId: 'test-physical-id',
        ServiceToken: 'myServiceToken',
      };

      const context: Context = {
        callbackWaitsForEmptyEventLoop: false,
        functionName: 'test-function',
        functionVersion: '1',
        invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
        memoryLimitInMB: '128',
        awsRequestId: 'test-aws-request-id',
        logGroupName: '/aws/lambda/test-function',
        logStreamName: '2023/01/01/[$LATEST]test-stream',
        getRemainingTimeInMillis: () => 30000,
        done: jest.fn(),
        fail: jest.fn(),
        succeed: jest.fn(),
      };

      const filenamesFromManifest = ['index.html', 'static/css/main.b4f55c7e.css', 'static/js/main.c838e191.js'];
      const manifestContent = JSON.stringify({ files: filenamesFromManifest });

      // Mock CloudFormation response
      const cfnResponseScope = nock('https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com')
        .put('/test-response-url')
        .reply(200);

      // Mock the manifest file read
      s3Mock
        .on(GetObjectCommand, {
          Bucket: config.SrcBucket,
          Key: webuiSrcPath + 'webui-manifest.json',
        })
        .resolves({
          Body: {
            transformToString: async () => manifestContent,
          } as any,
        });

      // Mock file copies
      for (const filename of filenamesFromManifest) {
        s3Mock
          .on(CopyObjectCommand, {
            CopySource: `${config.SrcBucket}/${webuiSrcPath}${filename}`,
            Bucket: config.WebUIBucket,
            Key: filename,
          })
          .resolves({});
      }

      // Mock config file write
      s3Mock
        .on(PutObjectCommand, {
          Bucket: config.WebUIBucket,
          Key: 'aws-exports.json',
        })
        .resolves({});

      // ACT
      await lambdaHandler(event, context);

      // ASSERT
      // Verify CloudFormation response was sent
      expect(cfnResponseScope.isDone()).toBe(true);

      // Verify S3 operations were performed
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(CopyObjectCommand)).toHaveLength(filenamesFromManifest.length);
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
    });

    it('should handle lambda Delete event and send success response without deployment', async () => {
      // ARRANGE
      const responseUrl = 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/test-response-url';
      const event: CloudFormationCustomResourceEvent = {
        RequestType: 'Delete',
        ResponseURL: responseUrl,
        StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345678-1234-1234-1234-123456789012',
        RequestId: 'test-request-id',
        LogicalResourceId: 'WebUIDeployment',
        ResourceType: 'Custom::WebUIDeployment',
        ResourceProperties: {
          ServiceToken: 'myServiceToken',
        },
        PhysicalResourceId: 'test-physical-id',
        ServiceToken: 'myServiceToken',
      };

      const context: Context = {
        callbackWaitsForEmptyEventLoop: false,
        functionName: 'test-function',
        functionVersion: '1',
        invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
        memoryLimitInMB: '128',
        awsRequestId: 'test-aws-request-id',
        logGroupName: '/aws/lambda/test-function',
        logStreamName: '2023/01/01/[$LATEST]test-stream',
        getRemainingTimeInMillis: () => 30000,
        done: jest.fn(),
        fail: jest.fn(),
        succeed: jest.fn(),
      };

      // Mock CloudFormation response
      const cfnResponseScope = nock('https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com')
        .put('/test-response-url')
        .reply(200);

      // ACT
      await lambdaHandler(event, context);

      // ASSERT
      // Verify CloudFormation response was sent
      expect(cfnResponseScope.isDone()).toBe(true);

      // Verify no S3 operations were performed for Delete
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
      expect(s3Mock.commandCalls(CopyObjectCommand)).toHaveLength(0);
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(0);
    });

    it('should handle errors and send failure response', async () => {
      // ARRANGE
      const responseUrl = 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/test-response-url';
      const event: CloudFormationCustomResourceEvent = {
        RequestType: 'Create',
        ResponseURL: responseUrl,
        StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/12345678-1234-1234-1234-123456789012',
        RequestId: 'test-request-id',
        LogicalResourceId: 'WebUIDeployment',
        ResourceType: 'Custom::WebUIDeployment',
        ResourceProperties: {
          ServiceToken: 'myServiceToken',
        },
        ServiceToken: 'myServiceToken',
      };

      const context: Context = {
        callbackWaitsForEmptyEventLoop: false,
        functionName: 'test-function',
        functionVersion: '1',
        invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
        memoryLimitInMB: '128',
        awsRequestId: 'test-aws-request-id',
        logGroupName: '/aws/lambda/test-function',
        logStreamName: '2023/01/01/[$LATEST]test-stream',
        getRemainingTimeInMillis: () => 30000,
        done: jest.fn(),
        fail: jest.fn(),
        succeed: jest.fn(),
      };

      // Mock CloudFormation response
      const cfnResponseScope = nock('https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com')
        .put('/test-response-url')
        .reply(200);

      // Mock S3 error
      s3Mock.on(GetObjectCommand).rejects(new Error('S3 operation failed'));

      // ACT
      await lambdaHandler(event, context);

      // ASSERT
      // Verify CloudFormation response was sent
      expect(cfnResponseScope.isDone()).toBe(true);
    });
  });
});
