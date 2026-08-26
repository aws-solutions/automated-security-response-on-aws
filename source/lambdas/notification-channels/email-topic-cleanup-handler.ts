// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CloudFormationCustomResourceEvent, Context } from 'aws-lambda';
import { SNSClient, ListTopicsCommand, DeleteTopicCommand } from '@aws-sdk/client-sns';
import { getLogger } from '../common/utils/logger';

import { emailTopicCleanupEnvironment } from './emailTopicCleanupEnvironment';

const logger = getLogger('email_topic_cleanup');

/** Outcome reported back to CloudFormation via the pre-signed response URL. */
interface CleanupOutcome {
  readonly status: 'SUCCESS' | 'FAILED';
  readonly message: string;
}

/** Safe `Error.message` extraction for `unknown` values from try/catch. */
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown error';
}

export class EmailTopicCleanupHandler {
  // Lazily resolved on first use so a misconfigured env var surfaces as a handler
  // error caught by the outer try/catch — never at module load. If the env throw
  // happened in the constructor, the module-level `new EmailTopicCleanupHandler()`
  // below would prevent the Lambda from initializing, so the custom resource
  // would never reply to CloudFormation and the stack would wedge until timeout.
  private cachedTopicPrefix: string | undefined;

  constructor(private readonly snsClient: SNSClient = new SNSClient({})) {}

  private getTopicPrefix(): string {
    this.cachedTopicPrefix ??= emailTopicCleanupEnvironment().TOPIC_PREFIX;
    return this.cachedTopicPrefix;
  }

  @logger.injectLambdaContext()
  async handler(event: CloudFormationCustomResourceEvent, context: Context): Promise<void> {
    // CloudFormation custom resources MUST always send a response, otherwise the
    // stack hangs in *_IN_PROGRESS until the 1-hour timeout. The outer try/catch
    // ensures we ALWAYS reach `sendResponseSafely` no matter what fails inside.
    let outcome: CleanupOutcome;
    try {
      logger.info('Email topic cleanup invoked', { requestType: event.RequestType });
      outcome = await this.processRequest(event);
    } catch (error) {
      // Defensive: catches anything thrown before/around `processRequest`
      // (e.g. logger init). On Delete we still report SUCCESS so the stack can
      // finish deleting; on Create/Update we surface FAILED so the stack rolls
      // back immediately rather than waiting for the 1-hour timeout.
      logger.error('Unexpected error in email topic cleanup handler', { error });
      outcome = {
        status: event.RequestType === 'Delete' ? 'SUCCESS' : 'FAILED',
        message: errorMessage(error),
      };
    }

    await this.sendResponseSafely(event, context, outcome);
  }

  /**
   * Run the request-type-specific work and translate any failure into a
   * CleanupOutcome. Pulled out of `handler` so the cognitive complexity of
   * the request flow stays low and the outer try/catch only handles the
   * defensive "everything else" path.
   */
  private async processRequest(event: CloudFormationCustomResourceEvent): Promise<CleanupOutcome> {
    try {
      if (event.RequestType === 'Delete') {
        const deleted = await this.deleteAllAsrTopics();
        return { status: 'SUCCESS', message: `Deleted ${deleted} ASR email notification topics` };
      }
      return { status: 'SUCCESS', message: `No action for ${event.RequestType}` };
    } catch (error) {
      logger.error('Email topic cleanup failed', { error });
      if (event.RequestType === 'Delete') {
        // Best-effort on Delete: still report SUCCESS so the stack can finish deleting.
        return { status: 'SUCCESS', message: `Cleanup failed (best-effort): ${errorMessage(error)}` };
      }
      return { status: 'FAILED', message: errorMessage(error) };
    }
  }

  /**
   * Wrapper around `sendResponse` that swallows any error. CloudFormation custom
   * resources have only one chance to reply via the pre-signed URL — if it fails,
   * the stack will eventually time out, and re-throwing would only delay that.
   */
  private async sendResponseSafely(
    event: CloudFormationCustomResourceEvent,
    context: Context,
    outcome: CleanupOutcome,
  ): Promise<void> {
    try {
      await this.sendResponse(event, context, outcome);
    } catch (error) {
      // Swallow: nothing we can do — log so the operator can investigate the timeout.
      logger.error('Failed to send response to CloudFormation; stack may stay stuck until timeout', { error });
    }
  }

  private async deleteAllAsrTopics(): Promise<number> {
    const topicArns = await this.listAsrTopics();
    logger.info('Found ASR email notification topics', { count: topicArns.length });

    let deleted = 0;
    for (const arn of topicArns) {
      try {
        await this.snsClient.send(new DeleteTopicCommand({ TopicArn: arn }));
        deleted++;
        logger.info('Deleted topic', { topicArn: arn });
      } catch (error) {
        logger.error('Failed to delete topic, continuing', { topicArn: arn, error });
      }
    }
    return deleted;
  }

  private async listAsrTopics(): Promise<string[]> {
    const arns: string[] = [];
    let nextToken: string | undefined;

    do {
      const result = await this.snsClient.send(new ListTopicsCommand({ NextToken: nextToken }));
      for (const topic of result.Topics ?? []) {
        if (topic.TopicArn && this.isAsrEmailTopic(topic.TopicArn)) {
          arns.push(topic.TopicArn);
        }
      }
      nextToken = result.NextToken;
    } while (nextToken);

    return arns;
  }

  private isAsrEmailTopic(arn: string): boolean {
    const topicName = arn.split(':').pop() ?? '';
    return topicName.startsWith(this.getTopicPrefix());
  }

  private async sendResponse(
    event: CloudFormationCustomResourceEvent,
    context: Context,
    outcome: CleanupOutcome,
  ): Promise<void> {
    const body = JSON.stringify({
      Status: outcome.status,
      Reason: `See CloudWatch Log Stream: ${context.logStreamName}`,
      PhysicalResourceId: event.LogicalResourceId,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      Data: { Message: outcome.message },
    });

    // `fetch` only rejects on network-level failures, not on HTTP 4xx/5xx, so we
    // must explicitly check `response.ok`. Otherwise an expired pre-signed URL
    // (403) or a transient 5xx would silently look like success and CloudFormation
    // would never receive the response, leaving the stack stuck until timeout.
    // Errors are propagated to `sendResponseSafely`, which owns logging.
    const response = await fetch(event.ResponseURL, {
      method: 'PUT',
      headers: { 'Content-Type': '', 'Content-Length': Buffer.byteLength(body).toString() },
      body,
    });
    if (!response.ok) {
      throw new Error(`CloudFormation response failed with status ${response.status} ${response.statusText}`);
    }
  }
}

const instance = new EmailTopicCleanupHandler();
export const handler = instance.handler.bind(instance);
