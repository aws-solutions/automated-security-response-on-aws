// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const {
  PutLogEventsCommand,
  CreateLogStreamCommand,
  CloudWatchLogsClient,
} = require('@aws-sdk/client-cloudwatch-logs');
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');
const logGroupName = process.env.LOG_GROUP_NAME ?? '/aws/lambda/SO0111-ASR-CloudTrailEvents';

const s3Client = new S3Client({});
const stsClient = new STSClient({});

async function getLogsFromS3(bucket, key) {
  const command = new GetObjectCommand({ Bucket: bucket, Key: key });
  const response = await s3Client.send(command);

  // CloudTrail data in S3 is compressed in .gz, need to decompress before processing the logs
  const compressedData = await response.Body.transformToByteArray();

  const decompressedData = await new Promise((resolve, reject) => {
    const zlib = require('zlib');
    zlib.gunzip(compressedData, (err, data) => {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
  return JSON.parse(decompressedData.toString());
}

function filterForAsrEvents(cloudTrailLog) {
  return cloudTrailLog.Records.filter((record) => {
    return (
      record.sourceIPAddress === 'ssm.amazonaws.com' &&
      record.userIdentity.arn.indexOf('SO0111') > -1 &&
      record.eventName !== 'StartAutomationExecution' &&
      record.eventName !== 'BatchUpdateFindings'
    );
  }).map(
    ({
      eventSource,
      eventName,
      awsRegion,
      eventTime,
      requestParameters,
      responseElements,
      recipientAccountId,
      resources,
    }) => {
      console.debug(eventName, eventSource);
      const actionLogRecord = {
        eventSource,
        eventName,
        awsRegion,
        eventTime,
        requestParameters,
        responseElements,
        recipientAccountId,
        resources,
      };
      return {
        timestamp: new Date(eventTime).getTime(),
        message: JSON.stringify(actionLogRecord),
      };
    },
  );
}

async function assumeRoleInAdminAccount(AssumeRoleCommand, stsClient) {
  const { CloudWatchLogsClient } = require('@aws-sdk/client-cloudwatch-logs');
  const assumeRoleCommand = new AssumeRoleCommand({
    RoleArn: process.env.LOG_WRITER_ROLE_ARN,
    RoleSessionName: 'EventProcessorSession',
  });
  const assumeRoleResponse = await stsClient.send(assumeRoleCommand);

  // Create CloudWatch Logs client with the assumed role credentials
  return new CloudWatchLogsClient({
    credentials: {
      accessKeyId: assumeRoleResponse.Credentials.AccessKeyId,
      secretAccessKey: assumeRoleResponse.Credentials.SecretAccessKey,
      sessionToken: assumeRoleResponse.Credentials.SessionToken,
    },
  });
}

async function sendToCloudWatchLogGroup(asrEvents) {
  console.debug('Sending to CloudWatch Logs', asrEvents);
  const logStreamName = new Date().toISOString().split('T')[0]; // use current date as logStreamName

  const putLogEventsCommand = new PutLogEventsCommand({
    logGroupName,
    logStreamName,
    logEvents: asrEvents,
  });

  const cloudwatchLogsClient = await assumeRoleInAdminAccount(AssumeRoleCommand, stsClient);

  try {
    await cloudwatchLogsClient.send(putLogEventsCommand);
  } catch (error) {
    if (error.name === 'ResourceNotFoundException') {
      // If the log stream doesn't exist, create it first
      const createLogStreamCommand = new CreateLogStreamCommand({
        logGroupName,
        logStreamName,
      });
      await cloudwatchLogsClient.send(createLogStreamCommand);

      // Then try sending the logs again
      await cloudwatchLogsClient.send(putLogEventsCommand);
    } else {
      throw error;
    }
  }
}

exports.handler = async (event) => {
  const bucket = event.Records[0].s3.bucket.name;
  const key = decodeURIComponent(event.Records[0].s3.object.key.replace(/\\+/g, ' '));
  const cloudTrailLog = await getLogsFromS3(bucket, key);

  if (!cloudTrailLog.Records) {
    console.debug('No Records in Log', cloudTrailLog);
    return { statusCode: 204, body: 'No Records to filter' };
  }

  const asrEvents = filterForAsrEvents(cloudTrailLog);

  // If we found events created by ASR solution, send them to CloudWatch Logs
  if (asrEvents.length > 0) {
    await sendToCloudWatchLogGroup(asrEvents);
  }

  return { statusCode: 200, body: { message: 'Successfully processed CloudTrail log', count: asrEvents.length } };
};
