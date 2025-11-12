// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { CopyObjectCommand, GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { ASRS3Client } from '../../clients/ASRS3Client';
import { MAX_PRESIGNED_URL_EXPIRY_SECONDS } from '../../../common/constants/apiConstant';

const s3Mock = mockClient(S3Client);

describe('S3 Service', () => {
  let s3Service: ASRS3Client;

  beforeEach(() => {
    s3Mock.reset();
    s3Service = new ASRS3Client();
    process.env.PRESIGNED_URL_TTL_DAYS = '7';
  });

  afterEach(() => {
    delete process.env.PRESIGNED_URL_TTL_DAYS;
  });

  describe('readJsonFile', () => {
    it('should read and parse JSON file successfully', async () => {
      // ARRANGE
      const bucketName = 'test-bucket';
      const fileName = 'test.json';
      const jsonContent = { key: 'value', number: 123 };
      const jsonString = JSON.stringify(jsonContent);

      s3Mock
        .on(GetObjectCommand, {
          Bucket: bucketName,
          Key: fileName,
        })
        .resolves({
          Body: { transformToString: async () => jsonString } as any,
        });

      // ACT
      const result = await s3Service.readJsonFile(bucketName, fileName);

      // ASSERT
      expect(result).toEqual(jsonContent);
      expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(1);
    });

    it('should throw error when no body in response', async () => {
      // ARRANGE
      const bucketName = 'test-bucket';
      const fileName = 'test.json';

      s3Mock
        .on(GetObjectCommand, {
          Bucket: bucketName,
          Key: fileName,
        })
        .resolves({
          Body: undefined,
        });

      // ACT & ASSERT
      await expect(s3Service.readJsonFile(bucketName, fileName)).rejects.toThrow('No body in S3 response');
    });
  });

  describe('copyFile', () => {
    it('should copy file successfully', async () => {
      // ARRANGE
      const sourceBucket = 'source-bucket';
      const targetBucket = 'target-bucket';
      const sourcePrefix = 'source/';
      const targetPrefix = 'target/';
      const fileName = 'test.txt';

      s3Mock
        .on(CopyObjectCommand, {
          CopySource: `${sourceBucket}/${sourcePrefix}${fileName}`,
          Bucket: targetBucket,
          Key: `${targetPrefix}${fileName}`,
        })
        .resolves({});

      // ACT
      await s3Service.copyFile(sourceBucket, targetBucket, sourcePrefix, targetPrefix, fileName);

      // ASSERT
      expect(s3Mock.commandCalls(CopyObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(CopyObjectCommand)[0].args[0].input).toEqual({
        CopySource: `${sourceBucket}/${sourcePrefix}${fileName}`,
        Bucket: targetBucket,
        Key: `${targetPrefix}${fileName}`,
      });
    });

    it('should handle copy errors', async () => {
      // ARRANGE
      const sourceBucket = 'source-bucket';
      const targetBucket = 'target-bucket';
      const sourcePrefix = 'source/';
      const targetPrefix = 'target/';
      const fileName = 'test.txt';

      const error = new Error('Access denied');
      error.name = 'AccessDenied';
      s3Mock.on(CopyObjectCommand).rejects(error);

      // ACT & ASSERT
      await expect(
        s3Service.copyFile(sourceBucket, targetBucket, sourcePrefix, targetPrefix, fileName),
      ).rejects.toThrow('Access denied');
    });
  });

  describe('writeJsonAsFile', () => {
    it('should write JSON object as file successfully', async () => {
      // ARRANGE
      const bucketName = 'test-bucket';
      const fileName = 'test.json';
      const jsonObject = { key: 'value', number: 123 };

      s3Mock
        .on(PutObjectCommand, {
          Bucket: bucketName,
          Key: fileName,
          Body: JSON.stringify(jsonObject),
          ContentType: 'application/json',
          Metadata: {
            'Content-Type': 'application/json',
          },
        })
        .resolves({});

      // ACT
      await s3Service.writeJsonAsFile(bucketName, fileName, jsonObject);

      // ASSERT
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(PutObjectCommand)[0].args[0].input).toEqual({
        Bucket: bucketName,
        Key: fileName,
        Body: JSON.stringify(jsonObject),
        ContentType: 'application/json',
        Metadata: {
          'Content-Type': 'application/json',
        },
      });
    });

    it('should handle write errors', async () => {
      // ARRANGE
      const bucketName = 'test-bucket';
      const fileName = 'test.json';
      const jsonObject = { key: 'value' };

      const error = new Error('Access denied');
      s3Mock.on(PutObjectCommand).rejects(error);

      // ACT & ASSERT
      await expect(s3Service.writeJsonAsFile(bucketName, fileName, jsonObject)).rejects.toThrow('Access denied');
    });
  });

  describe('uploadCsvAndGeneratePresignedUrl', () => {
    it('should upload CSV and generate presigned URL successfully', async () => {
      // ARRANGE
      const bucketName = 'test-bucket';
      const fileName = 'test-export.csv';
      const csvContent = 'header1,header2\nvalue1,value2';

      s3Mock
        .on(PutObjectCommand, {
          Bucket: bucketName,
          Key: fileName,
          Body: csvContent,
          ContentType: 'text/csv',
          ContentDisposition: `attachment; filename="${fileName}"`,
        })
        .resolves({});

      // ACT
      const result = await s3Service.uploadCsvAndGeneratePresignedUrl(bucketName, fileName, csvContent);

      // ASSERT
      expect(result).toMatch(/^https:\/\/.*\.s3\..*\.amazonaws\.com\/.*\?.*$/); // Real presigned URL format
      expect(s3Mock.commandCalls(PutObjectCommand)).toHaveLength(1);
      expect(s3Mock.commandCalls(PutObjectCommand)[0].args[0].input).toEqual({
        Bucket: bucketName,
        Key: fileName,
        Body: csvContent,
        ContentType: 'text/csv',
        ContentDisposition: `attachment; filename="${fileName}"`,
      });
    });

    it('should use custom TTL from environment variable', async () => {
      // ARRANGE
      process.env.PRESIGNED_URL_TTL_DAYS = '3';
      const bucketName = 'test-bucket';
      const fileName = 'test-export.csv';
      const csvContent = 'header1,header2\nvalue1,value2';

      s3Mock.on(PutObjectCommand).resolves({});

      // ACT
      const result = await s3Service.uploadCsvAndGeneratePresignedUrl(bucketName, fileName, csvContent);

      // ASSERT
      expect(result).toMatch(/^https:\/\/.*\.s3\..*\.amazonaws\.com\/.*\?.*$/); // Real presigned URL format
      // The TTL is embedded in the URL, so we can verify it by checking the Expires parameter
      const url = new URL(result);
      const expires = url.searchParams.get('X-Amz-Expires');
      expect(expires).toBe('86400');
    });

    it('should enforce AWS maximum of 7 days', async () => {
      // ARRANGE
      process.env.PRESIGNED_URL_TTL_DAYS = '10'; // More than AWS maximum
      const bucketName = 'test-bucket';
      const fileName = 'test-export.csv';
      const csvContent = 'header1,header2\nvalue1,value2';

      s3Mock.on(PutObjectCommand).resolves({});

      // ACT
      const result = await s3Service.uploadCsvAndGeneratePresignedUrl(bucketName, fileName, csvContent);

      // ASSERT
      expect(result).toMatch(/^https:\/\/.*\.s3\..*\.amazonaws\.com\/.*\?.*$/); // Real presigned URL format
      // The TTL should be capped at 1 day
      const url = new URL(result);
      const expires = url.searchParams.get('X-Amz-Expires');
      expect(expires).toBe(MAX_PRESIGNED_URL_EXPIRY_SECONDS.toString());
    });

    it('should handle upload errors', async () => {
      // ARRANGE
      const bucketName = 'test-bucket';
      const fileName = 'test-export.csv';
      const csvContent = 'header1,header2\nvalue1,value2';

      const error = new Error('Upload failed');
      s3Mock.on(PutObjectCommand).rejects(error);

      // ACT & ASSERT
      await expect(s3Service.uploadCsvAndGeneratePresignedUrl(bucketName, fileName, csvContent)).rejects.toThrow(
        'Upload failed',
      );
    });
  });
});
