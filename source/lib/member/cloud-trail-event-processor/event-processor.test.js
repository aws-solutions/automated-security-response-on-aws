// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const { mockClient } = require('aws-sdk-client-mock');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');
const { CloudWatchLogsClient, PutLogEventsCommand } = require('@aws-sdk/client-cloudwatch-logs');
jest.mock('zlib');

const irrelevantEvent = {
  eventVersion: '1.08',
  userIdentity: {
    type: 'AssumedRole',
    principalId: 'AROAWKUYOI766DL3JW2PI:waf-sec-automations-ReputationListsParser-STLIU7TFqJkK',
    arn: 'arn:aws:sts::123456789012:assumed-role/waf-sec-automations-LambdaRoleReputationListsParser-bWMw2JGL0CaN/waf-sec-automations-ReputationListsParser-STLIU7TFqJkK',
    accountId: '123456789012',
    accessKeyId: 'ASIAWXXXYYYZZZ',
    sessionContext: {
      sessionIssuer: [{}],
      webIdFederationData: {},
      attributes: [{}],
    },
  },
  eventTime: '2024-11-07T16:31:27Z',
  eventSource: 'wafv2.amazonaws.com',
  eventName: 'UpdateIPSet',
  awsRegion: 'eu-central-1',
  sourceIPAddress: 'x.y.z.a',
  userAgent:
    'Boto3/1.34.145 md/Botocore#1.34.145 ua/2.0 os/linux#5.10.226-235.879.amzn2.x86_64 md/arch#x86_64 lang/python#3.10.14 md/pyimpl#CPython exec-env/AWS_Lambda_python3.10 cfg/retry-mode#standard Botocore/1.34.145 AwsSolution/SO0006/v4.0.4',
  requestParameters: {
    name: 'waf-sec-automationsIPReputationListsSetIPV4',
    scope: 'REGIONAL',
    id: 'fddea71a-6c8c-422e-a6e9-8fb4d5a4e2e7',
    description: 'Block Reputation List IPV4 addresses',
    addresses: ['y.d.k.g/20', 'a.h.ty.v/16', 'jfd.kg.l.dhj/18'],
    lockToken: 'f3f075b2-95c9-469d-b2d2-0aea7a4e4c1a',
  },
  responseElements: { nextLockToken: '58a72e11-e7f4-4a75-b20b-4503f79d169b' },
  requestID: '7b4ed82b-69b1-4123-b452-77bcd46fc7a2',
  eventID: 'e5e20f35-bc9c-45ce-a3ec-c50ce9a2dc68',
  readOnly: false,
  eventType: 'AwsApiCall',
  apiVersion: '2019-04-23',
  managementEvent: true,
  recipientAccountId: '123456789012',
  eventCategory: 'Management',
  tlsDetails: {
    tlsVersion: 'TLSv1.3',
    cipherSuite: 'TLS_AES_128_GCM_SHA256',
    clientProvidedHostHeader: 'wafv2.eu-central-1.amazonaws.com',
  },
};

const asrCloudTrailEvent = {
  eventVersion: '1.10',
  userIdentity: {
    type: 'AssumedRole',
    principalId: 'AROAWKUYOI76W4KTMFYWA:Automation-33fc2b9c-6ce5-4206-89a9-3e0fdcafe9b6',
    arn: 'arn:aws:sts::123456789012:assumed-role/SO0111-ConfigureS3BucketPublicAccessBlock-30298542/Automation-33fc2b9c-6ce5-4206-89a9-3e0fdcafe9b6',
    accountId: '123456789012',
    accessKeyId: 'ASIAWXXXYYYZZZ',
    sessionContext: { sessionIssuer: [{}], attributes: [{}] },
    invokedBy: 'ssm.amazonaws.com',
  },
  eventTime: '2024-11-07T16:48:09Z',
  eventSource: 's3.amazonaws.com',
  eventName: 'PutBucketPublicAccessBlock',
  awsRegion: 'us-east-1',
  sourceIPAddress: 'ssm.amazonaws.com',
  userAgent: 'ssm.amazonaws.com',
  requestParameters: {
    publicAccessBlock: '',
    bucketName: 'aa106-test-s3bucket07682993-otbr2z6u0cta',
    PublicAccessBlockConfiguration: {
      xmlns: 'http://s3.amazonaws.com/doc/2006-03-01/',
      RestrictPublicBuckets: true,
      BlockPublicPolicy: true,
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
    },
    Host: 'aa106-test-s3bucket07682993-otbr2z6u0cta.s3.amazonaws.com',
  },
  responseElements: null,
  additionalEventData: {
    SignatureVersion: 'SigV4',
    CipherSuite: 'TLS_AES_128_GCM_SHA256',
    bytesTransferredIn: 287,
    AuthenticationMethod: 'AuthHeader',
    'x-amz-id-2': 'MDXh6vgATe0yUglQ88qekZfGaPL0l4STK+jfwUUY2+0gx8U3heHKH8nCOAoLZDbyTvylGnGkotw=',
    bytesTransferredOut: 0,
  },
  requestID: '9NZ7DG3ERC53JT38',
  eventID: '3c4e1ff0-d14a-4860-8bca-ed7ebeb82900',
  readOnly: false,
  resources: [
    {
      accountId: '123456789012',
      type: 'AWS::S3::Bucket',
      ARN: 'arn:aws:s3:::aa106-test-s3bucket07682993-otbr2z6u0cta',
    },
  ],
  eventType: 'AwsApiCall',
  managementEvent: true,
  recipientAccountId: '123456789012',
  eventCategory: 'Management',
};

const expectedResult = {
  eventSource: 's3.amazonaws.com',
  eventName: 'PutBucketPublicAccessBlock',
  awsRegion: 'us-east-1',
  eventTime: '2024-11-07T16:48:09Z',
  requestParameters: {
    publicAccessBlock: '',
    bucketName: 'aa106-test-s3bucket07682993-otbr2z6u0cta',
    PublicAccessBlockConfiguration: {
      xmlns: 'http://s3.amazonaws.com/doc/2006-03-01/',
      RestrictPublicBuckets: true,
      BlockPublicPolicy: true,
      BlockPublicAcls: true,
      IgnorePublicAcls: true,
    },
    Host: 'aa106-test-s3bucket07682993-otbr2z6u0cta.s3.amazonaws.com',
  },
  responseElements: null,
  recipientAccountId: '123456789012',
  resources: [
    {
      ARN: 'arn:aws:s3:::aa106-test-s3bucket07682993-otbr2z6u0cta',
      accountId: '123456789012',
      type: 'AWS::S3::Bucket',
    },
  ],
};

const s3Notification = {
  s3SchemaVersion: '1.0',
  configurationId: 'OTllOGY2YTYtODFiMC00OTliLTlkMDItODRjNTQzMjJmNWJm',
  bucket: {
    name: 'asr-member-27211-managementeventsbucketefc9164c-ty0gvc2bl01b',
    ownerIdentity: {
      principalId: 'A1P1A1UEPDNGFB',
    },
    arn: 'arn:aws:s3:::asr-member-27211-managementeventsbucketefc9164c-ty0gvc2bl01b',
  },
  object: {
    key: 'AWSLogs/123456789012/CloudTrail/eu-north-1/2024/11/07/435185141757_CloudTrail_eu-north-1_20241107T2000Z_jj0LvUD9CK69mEZu.json.gz',
    size: 3060,
    eTag: '5de5527e50dc9d335be6b539ac3474a6',
    sequencer: '00672D1BF728EEBFD0',
  },
};

test('ignores events without Records', async () => {
  // GIVEN
  const s3ClientMock = mockClient(S3Client);
  s3ClientMock.on(GetObjectCommand).resolvesOnce({
    Body: {
      transformToByteArray: () => [],
    },
  });
  const zlib = require('zlib');
  zlib.gunzip = jest.fn();
  zlib.gunzip.mockImplementation((data, callback) => {
    setImmediate(() => {
      callback(null, Buffer.from(JSON.stringify({})));
    });
  });

  // WHEN
  const { handler } = require('./event-processor');

  // THEN
  const result = await handler({ Records: [{ s3: s3Notification }] });
  expect(result.statusCode).toEqual(204);
});

test('ignores events from irrelevant sources', async () => {
  // GIVEN
  const s3ClientMock = mockClient(S3Client);
  s3ClientMock.on(GetObjectCommand).resolvesOnce({
    Body: {
      transformToByteArray: () => [],
    },
  });
  const zlib = require('zlib');
  zlib.gunzip = jest.fn();
  zlib.gunzip.mockImplementation((data, callback) => {
    setImmediate(() => {
      callback(null, Buffer.from(JSON.stringify({ Records: [irrelevantEvent] })));
    });
  });

  const stsClientMock = mockClient(STSClient);
  const cloudWatchClientMock = mockClient(CloudWatchLogsClient);

  // WHEN
  const { handler } = require('./event-processor');
  const result = await handler({ Records: [{ s3: s3Notification }] });

  // THEN
  expect(result.body.count).toEqual(0);

  expect(stsClientMock.calls()).toHaveLength(0);
  expect(cloudWatchClientMock.calls()).toHaveLength(0);
});

test('sends ASR events to CloudWatch', async () => {
  // GIVEN
  const s3ClientMock = mockClient(S3Client);
  s3ClientMock.on(GetObjectCommand).resolvesOnce({
    Body: {
      transformToByteArray: () => [],
    },
  });
  const zlib = require('zlib');
  zlib.gunzip = jest.fn();
  zlib.gunzip.mockImplementation((data, callback) => {
    setImmediate(() => {
      callback(null, Buffer.from(JSON.stringify({ Records: [asrCloudTrailEvent] })));
    });
  });

  const stsClientMock = mockClient(STSClient);
  stsClientMock.on(AssumeRoleCommand).resolvesOnce({
    Credentials: {
      AccessKeyId: 'foo',
      SecretAccessKey: 'bar',
      SessionToken: 'baz',
    },
  });
  const cloudWatchClientMock = mockClient(CloudWatchLogsClient);
  cloudWatchClientMock.on(PutLogEventsCommand).rejectsOnce({
    name: 'ResourceNotFoundException',
  });

  // WHEN
  const { handler } = require('./event-processor');
  const result = await handler({ Records: [{ s3: s3Notification }] });

  // THEN
  expect(result.body.count).toEqual(1);

  const putLogEventsCalls = cloudWatchClientMock.commandCalls(PutLogEventsCommand);
  expect(putLogEventsCalls).toHaveLength(2);
  const firstCallInput = putLogEventsCalls[1].args[0].input;

  expect(firstCallInput.logGroupName).toEqual('/aws/lambda/SO0111-ASR-CloudTrailEvents');
  expect(firstCallInput.logStreamName).toEqual(new Date().toISOString().split('T')[0]);
  expect(JSON.parse(firstCallInput.logEvents[0].message)).toEqual(expectedResult);
});
