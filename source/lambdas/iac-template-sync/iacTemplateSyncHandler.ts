// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import type { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { getLogger } from '../common/utils/logger';
import { getTracer } from '../common/utils/tracer';
import { Manifest, manifestSchema, ResourceProperties, SyncResult, TemplateEntry } from './types';
import { diffManifests } from './manifestDiff';

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'automated-security-response-on-aws';

const tracer = getTracer(SOLUTION_TRADEMARKEDNAME);
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);

export class IaCTemplateSyncHandler implements LambdaInterface {
  private readonly s3Client: S3Client;

  constructor(s3Client: S3Client = new S3Client({})) {
    this.s3Client = tracer.captureAWSv3Client(s3Client);
  }

  @tracer.captureLambdaHandler()
  @logger.injectLambdaContext()
  async handler(event: CloudFormationCustomResourceEvent, context: Context): Promise<void> {
    logger.info('IaC template sync custom resource invoked', {
      requestType: event.RequestType,
      logicalResourceId: event.LogicalResourceId,
    });

    let result: SyncResult;
    try {
      result = await this.processEvent(event);
    } catch (error) {
      logger.error('Unhandled exception in IaC template sync', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      result = {
        status: 'FAILED',
        data: { Message: error instanceof Error ? error.message : 'Unknown error occurred' },
      };
    }

    try {
      await this.sendResponse(event, context, result.status, result.data);
    } catch (responseError) {
      logger.error('Failed to send response to CloudFormation', { responseError });
    }
  }

  private async processEvent(event: CloudFormationCustomResourceEvent): Promise<SyncResult> {
    const props: ResourceProperties = {
      SolutionsBucketName: event.ResourceProperties.SolutionsBucketName,
      CustomerBucketName: event.ResourceProperties.CustomerBucketName,
      ManifestKey: event.ResourceProperties.ManifestKey,
      SolutionVersion: event.ResourceProperties.SolutionVersion,
      TemplatePrefix: event.ResourceProperties.TemplatePrefix,
    };

    switch (event.RequestType) {
      case 'Create':
        return this.handleCreate(props);
      case 'Update':
        return this.handleUpdate(props);
      case 'Delete':
        return this.handleDelete();
    }
  }

  private async handleCreate(props: ResourceProperties): Promise<SyncResult> {
    try {
      const manifest = await this.fetchManifest(props.SolutionsBucketName, props.ManifestKey);

      for (const entry of manifest.templates) {
        await this.copyTemplate(props, entry);
      }

      await this.writeMetadata(props, manifest);

      logger.info('CREATE completed successfully', {
        templateCount: manifest.templates.length,
      });

      return {
        status: 'SUCCESS',
        data: { Message: `Copied ${manifest.templates.length} templates` },
      };
    } catch (error) {
      logger.error('CREATE failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        status: 'FAILED',
        data: { Message: error instanceof Error ? error.message : 'Unknown error occurred during CREATE' },
      };
    }
  }

  private async handleUpdate(props: ResourceProperties): Promise<SyncResult> {
    try {
      const incomingManifest = await this.fetchManifest(props.SolutionsBucketName, props.ManifestKey);

      let existingManifest: Manifest | undefined;
      try {
        existingManifest = await this.fetchManifest(props.CustomerBucketName, '.metadata/manifest.json');
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Unknown error';
        const isNotFound =
          error instanceof Error && (error.name === 'NoSuchKey' || error.message.includes('NoSuchKey'));
        if (isNotFound) {
          logger.warn('Existing manifest not found — falling back to CREATE behavior');
          return this.handleCreate(props);
        }
        // Any other error (corrupt manifest, transient S3 5xx, AccessDenied) — fail
        // loudly rather than falling back to CREATE which would overwrite bookkeeping.
        logger.error('Failed to fetch existing manifest — refusing destructive fallback', { error: message });
        return {
          status: 'FAILED',
          data: { Message: `Cannot read existing manifest; manual intervention required: ${message}` },
        };
      }

      const diff = diffManifests(existingManifest, incomingManifest);

      // Always overwrite solution-managed templates at root path
      for (const entry of [...diff.added, ...diff.updated]) {
        await this.copyTemplate(props, entry);
      }

      for (const entry of diff.deprecated) {
        await this.archiveDeprecatedTemplate(props, entry);
      }

      await this.writeMetadata(props, incomingManifest);

      const summary = [
        `added=${diff.added.length}`,
        `updated=${diff.updated.length}`,
        `deprecated=${diff.deprecated.length}`,
        `unchanged=${diff.unchanged.length}`,
      ].join(', ');

      logger.info('UPDATE completed successfully', { summary });

      return {
        status: 'SUCCESS',
        data: { Message: `UPDATE completed: ${summary}` },
      };
    } catch (error) {
      logger.error('UPDATE failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return {
        status: 'FAILED',
        data: { Message: error instanceof Error ? error.message : 'Unknown error occurred during UPDATE' },
      };
    }
  }

  private async fetchManifest(bucket: string, key: string): Promise<Manifest> {
    const response = await this.s3Client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    if (!response.Body) {
      throw new Error(`Empty response body for s3://${bucket}/${key}`);
    }
    const json = await response.Body.transformToString();
    let raw: unknown;
    try {
      raw = JSON.parse(json);
    } catch (parseError) {
      const detail = parseError instanceof Error ? parseError.message : 'unknown';
      throw new Error(`Invalid manifest at s3://${bucket}/${key}: malformed JSON: ${detail}`);
    }
    const parsed = manifestSchema.safeParse(raw);
    if (!parsed.success) {
      throw new Error(`Invalid manifest at s3://${bucket}/${key}: ${parsed.error.message}`);
    }
    return parsed.data;
  }

  /**
   * Writes the manifest to `.metadata/manifest.json`.
   */
  private async writeMetadata(props: ResourceProperties, manifest: Manifest): Promise<void> {
    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: props.CustomerBucketName,
        Key: '.metadata/manifest.json',
        Body: JSON.stringify(manifest, null, 2),
        ContentType: 'application/json',
      }),
    );
  }

  private async copyTemplate(props: ResourceProperties, entry: TemplateEntry): Promise<void> {
    const sourceKey = `${props.TemplatePrefix}${entry.s3Key}`;
    logger.info('Copying template', {
      source: `${props.SolutionsBucketName}/${sourceKey}`,
      destination: `${props.CustomerBucketName}/${entry.s3Key}`,
    });

    const templateResponse = await this.s3Client.send(
      new GetObjectCommand({
        Bucket: props.SolutionsBucketName,
        Key: sourceKey,
      }),
    );
    if (!templateResponse.Body) {
      throw new Error(`Empty response body for s3://${props.SolutionsBucketName}/${sourceKey}`);
    }
    const templateContent = await templateResponse.Body.transformToString();

    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: props.CustomerBucketName,
        Key: entry.s3Key,
        Body: templateContent,
      }),
    );
  }

  private async archiveDeprecatedTemplate(props: ResourceProperties, entry: TemplateEntry): Promise<void> {
    const archiveKey = `.deprecated/${entry.s3Key}`;
    logger.info('Archiving deprecated template', {
      controlId: entry.controlId,
      archiveDestination: `${props.CustomerBucketName}/${archiveKey}`,
    });

    try {
      await this.s3Client.send(
        new CopyObjectCommand({
          Bucket: props.CustomerBucketName,
          CopySource: `${props.CustomerBucketName}/${entry.s3Key}`,
          Key: archiveKey,
        }),
      );

      await this.s3Client.send(
        new DeleteObjectCommand({
          Bucket: props.CustomerBucketName,
          Key: entry.s3Key,
        }),
      );
    } catch (error) {
      logger.error('Failed to archive deprecated template — skipping deletion', {
        controlId: entry.controlId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  private handleDelete(): SyncResult {
    logger.info('DELETE event received — retaining all templates in customer bucket');
    return {
      status: 'SUCCESS',
      data: { Message: 'DELETE completed — templates retained' },
    };
  }

  private async sendResponse(
    event: CloudFormationCustomResourceEvent,
    context: Context,
    status: 'SUCCESS' | 'FAILED',
    data?: { Message: string },
  ): Promise<void> {
    const responseBody = JSON.stringify({
      Status: status,
      Reason: `See CloudWatch Log Stream: ${context.logStreamName}`,
      PhysicalResourceId: event.LogicalResourceId,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      Data: data ?? { Message: '' },
    });

    // Time-bound the CFN response PUT so a hung endpoint can't block the
    // Lambda for its full timeout.
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), 10_000);
    const options = {
      method: 'PUT',
      headers: {
        'Content-Type': '',
        'Content-Length': Buffer.byteLength(responseBody).toString(),
      },
      body: responseBody,
      signal: controller.signal,
    };

    try {
      const response = await fetch(event.ResponseURL, options);
      logger.info('CloudFormation response sent', {
        status: response.status,
        statusText: response.statusText,
      });
    } catch (error) {
      logger.error('Failed to send CloudFormation response', { error });
      throw error;
    } finally {
      clearTimeout(timeoutHandle);
    }
  }
}

const iacTemplateSyncHandler = new IaCTemplateSyncHandler();
export const handler = iacTemplateSyncHandler.handler.bind(iacTemplateSyncHandler);
