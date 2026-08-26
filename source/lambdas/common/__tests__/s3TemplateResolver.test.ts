// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import { GetObjectCommand, ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { Readable } from 'stream';
import { sdkStreamMixin } from '@smithy/util-stream';
import { S3TemplateResolver } from '../services/s3TemplateResolver';

const s3Mock = mockClient(S3Client);

const BUCKET_NAME = 'asr-iac-templates-test-us-east-1-123456789012';

function createSdkStream(content: string) {
  const stream = new Readable();
  stream.push(content);
  stream.push(null);
  return sdkStreamMixin(stream);
}

beforeEach(() => {
  s3Mock.reset();
});

describe('S3TemplateResolver', () => {
  const resolver = new S3TemplateResolver(BUCKET_NAME);

  it('lists the customized prefix first, falls back to default, then fetches content', async () => {
    const templateContent = 'resource "aws_s3_bucket" "example" {}';

    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [] })
      .resolvesOnce({ Contents: [{ Key: 'S3.1/terraform/S3.1.tf.txt' }] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: createSdkStream(templateContent),
    });

    const result = await resolver.resolve('S3.1', 'terraform');

    expect(result).toBe(templateContent);

    const listCalls = s3Mock.commandCalls(ListObjectsV2Command);
    expect(listCalls[0].args[0].input.Prefix).toBe('.customized/S3.1/terraform/');
    expect(listCalls[1].args[0].input.Prefix).toBe('S3.1/terraform/');

    const getCall = s3Mock.commandCalls(GetObjectCommand)[0].args[0].input;
    expect(getCall).toEqual({
      Bucket: BUCKET_NAME,
      Key: 'S3.1/terraform/S3.1.tf.txt',
    });
  });

  it('checks the customized prefix before the solution default prefix', async () => {
    const customizedContent = 'resource "aws_s3_bucket" "custom" {}';

    s3Mock.on(ListObjectsV2Command).resolvesOnce({ Contents: [{ Key: '.customized/S3.1/terraform/S3.1.tf.txt' }] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: createSdkStream(customizedContent),
    });

    const result = await resolver.resolve('S3.1', 'terraform');

    expect(result).toBe(customizedContent);
    // Customized prefix resolves, so the default prefix is never listed.
    const listCalls = s3Mock.commandCalls(ListObjectsV2Command);
    expect(listCalls).toHaveLength(1);
    expect(listCalls[0].args[0].input.Prefix).toBe('.customized/S3.1/terraform/');
  });

  it('falls back to the default prefix when no customized template exists', async () => {
    const defaultContent = 'resource "aws_s3_bucket" "default" {}';

    s3Mock
      .on(ListObjectsV2Command)
      .resolvesOnce({ Contents: [] })
      .resolvesOnce({ Contents: [{ Key: 'S3.1/terraform/S3.1.tf.txt' }] });
    s3Mock.on(GetObjectCommand).resolves({
      Body: createSdkStream(defaultContent),
    });

    const result = await resolver.resolve('S3.1', 'terraform');

    expect(result).toBe(defaultContent);
    const listCalls = s3Mock.commandCalls(ListObjectsV2Command);
    expect(listCalls).toHaveLength(2);
    expect(listCalls[0].args[0].input.Prefix).toBe('.customized/S3.1/terraform/');
    expect(listCalls[1].args[0].input.Prefix).toBe('S3.1/terraform/');
  });

  it('returns undefined when no files exist under the prefix', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });

    const result = await resolver.resolve('NonExistent.99', 'cdk');

    expect(result).toBeUndefined();
    expect(s3Mock.commandCalls(GetObjectCommand)).toHaveLength(0);
  });

  it('returns undefined when Contents is undefined', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({});

    const result = await resolver.resolve('NonExistent.99', 'cdk');

    expect(result).toBeUndefined();
  });

  it('throws on unexpected S3 errors from ListObjectsV2', async () => {
    const error = new Error('Access Denied');
    error.name = 'AccessDenied';
    s3Mock.on(ListObjectsV2Command).rejects(error);

    await expect(resolver.resolve('S3.1', 'cloudformation')).rejects.toThrow('Access Denied');
  });

  it('throws on unexpected S3 errors from GetObject', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: [{ Key: 'S3.1/cloudformation/S3.1.yaml.txt' }],
    });
    const error = new Error('Access Denied');
    error.name = 'AccessDenied';
    s3Mock.on(GetObjectCommand).rejects(error);

    await expect(resolver.resolve('S3.1', 'cloudformation')).rejects.toThrow('Access Denied');
  });
});
