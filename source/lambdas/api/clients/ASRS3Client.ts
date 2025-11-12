// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CopyObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Logger } from '@aws-lambda-powertools/logger';
import { MAX_PRESIGNED_URL_EXPIRY_SECONDS } from '../../common/constants/apiConstant';

export class ASRS3Client {
  private s3Client: S3Client;
  private logger: Logger;

  constructor(region?: string) {
    this.logger = new Logger({
      serviceName: 'S3',
      logLevel: (process.env.LOG_LEVEL as any) || 'INFO',
    });

    const currentRegion = region || process.env.AWS_REGION || 'us-east-1';

    this.s3Client = new S3Client({
      region: currentRegion,
    });
  }

  async readJsonFile(bucketName: string, fileQualifiedName: string): Promise<Record<string, any>> {
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: fileQualifiedName,
    });

    try {
      const response = await this.s3Client.send(command);

      if (!response.Body) {
        throw new Error('No body in S3 response');
      }

      const bodyContents = await response.Body.transformToString();
      return JSON.parse(bodyContents);
    } catch (error) {
      this.logger.error(`Failed to read JSON file ${fileQualifiedName} from bucket ${bucketName}:`, { error });
      throw error;
    }
  }

  async copyFile(
    sourceBucketName: string,
    targetBucketName: string,
    sourcePrefix: string,
    targetPrefix: string,
    fileName: string,
  ): Promise<void> {
    const sourceKey = sourcePrefix + fileName;
    const targetKey = targetPrefix + fileName;

    this.logger.debug(`Copy ${sourceKey} from ${sourceBucketName}`);

    const command = new CopyObjectCommand({
      CopySource: `${sourceBucketName}/${sourceKey}`,
      Bucket: targetBucketName,
      Key: targetKey,
    });

    try {
      await this.s3Client.send(command);
      this.logger.debug(`Copied ${targetKey} to ${targetBucketName}`);
    } catch (error: any) {
      this.logger.error(`Failed to copy key ${sourceKey}`);

      if (error.name === 'AccessDenied') {
        this.logger.error(
          'Access denied, make sure (1) the key exists in source bucket, (2) this lambda function ' +
            'has s3:read permissions to the source bucket and (3) s3:put permissions to the target bucket',
        );
      }

      this.logger.error('Copy error:', { error });
      throw error;
    }
  }

  async writeJsonAsFile(bucketName: string, qualifiedFileName: string, jsonObject: Record<string, any>): Promise<void> {
    const command = new PutObjectCommand({
      Bucket: bucketName,
      Key: qualifiedFileName,
      Body: JSON.stringify(jsonObject),
      ContentType: 'application/json',
      Metadata: {
        'Content-Type': 'application/json',
      },
    });

    try {
      await this.s3Client.send(command);
      this.logger.debug(`Successfully wrote JSON file ${qualifiedFileName} to bucket ${bucketName}`);
    } catch (error) {
      this.logger.error(`Failed to write JSON file ${qualifiedFileName} to bucket ${bucketName}:`, { error });
      throw error;
    }
  }

  async uploadCsvAndGeneratePresignedUrl(bucketName: string, fileName: string, csvContent: string): Promise<string> {
    const putCommand = new PutObjectCommand({
      Bucket: bucketName,
      Key: fileName,
      Body: csvContent,
      ContentType: 'text/csv',
      ContentDisposition: `attachment; filename="${fileName}"`,
    });

    try {
      await this.s3Client.send(putCommand);
      this.logger.debug(`Successfully uploaded CSV file ${fileName} to bucket ${bucketName}`);

      const getCommand = new GetObjectCommand({
        Bucket: bucketName,
        Key: fileName,
      });

      const ttlDays = Number(process.env.PRESIGNED_URL_TTL_DAYS) || 1;
      const expiresInSeconds = Math.min(ttlDays * 24 * 60 * 60, MAX_PRESIGNED_URL_EXPIRY_SECONDS);
      const presignedUrl = await getSignedUrl(this.s3Client, getCommand, {
        expiresIn: expiresInSeconds,
      });

      this.logger.debug('Successfully generated pre-signed URL', {
        fileName,
        bucketName,
        expiresInSeconds,
        expiresInDays: ttlDays,
      });

      return presignedUrl;
    } catch (error) {
      this.logger.error(`Failed to upload CSV file ${fileName} to bucket ${bucketName}:`, { error });
      throw error;
    }
  }
}
