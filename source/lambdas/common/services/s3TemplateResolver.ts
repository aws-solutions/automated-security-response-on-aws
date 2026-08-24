// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetObjectCommand, ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { TemplateResolver, TemplateType } from './iacGuidanceService';

export class S3TemplateResolver implements TemplateResolver {
  private readonly s3Client: S3Client;
  private readonly bucketName: string;

  constructor(bucketName: string, s3Client: S3Client = new S3Client({})) {
    this.bucketName = bucketName;
    this.s3Client = s3Client;
  }

  async resolve(sanitizedControlId: string, templateType: TemplateType): Promise<string | undefined> {
    // Check customer-customized path first, fall back to solution default.
    // This costs two ListObjectsV2 calls when no customization exists — acceptable
    // tradeoff for simplicity since most resolutions are infrequent (on-demand via API/notification).
    const customizedPrefix = `.customized/${sanitizedControlId}/${templateType}/`;
    const defaultPrefix = `${sanitizedControlId}/${templateType}/`;

    const content = await this.getFirstObject(customizedPrefix);
    if (content) {
      return content;
    }
    return this.getFirstObject(defaultPrefix);
  }

  private async getFirstObject(prefix: string): Promise<string | undefined> {
    const listResponse = await this.s3Client.send(
      new ListObjectsV2Command({
        Bucket: this.bucketName,
        Prefix: prefix,
        MaxKeys: 1,
      }),
    );

    const key = listResponse.Contents?.[0]?.Key;
    if (!key) {
      return undefined;
    }

    const getResponse = await this.s3Client.send(
      new GetObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      }),
    );

    return getResponse.Body?.transformToString();
  }
}
