// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import https from 'https';
import { DeleteParameterCommand, PutParameterCommand } from '@aws-sdk/client-ssm';
import { randomUUID } from 'crypto';
import { ASFFSchema, OCSFComplianceSchema } from '@asr/data-models';
import { getLogger } from './logger';
import { getCachedParameter, getSSMClient } from './ssmCache';

const SOLUTION_TRADEMARKEDNAME = process.env.SOLUTION_TRADEMARKEDNAME ?? 'unknown';
const logger = getLogger(SOLUTION_TRADEMARKEDNAME);
const AWS_ACCOUNT_ID = process.env.AWS_ACCOUNT_ID ?? 'unknown';
const STACK_ID = process.env.STACK_ID ?? 'unknown';

interface FailureMetric {
  status: string;
  status_reason: string;
  control_id: string | undefined;
  product_arn: string | undefined;
  region: string | undefined;
  error: string | undefined;
  truncatedRecordBody: string | undefined;
}

interface UsageData {
  Solution: string;
  UUID: string | undefined;
  TimeStamp: string;
  AccountId: string;
  StackId: string;
  Data: Record<string, any>;
  Version: string | undefined;
}

const SOLUTIONS_METRICS_ENDPOINT = 'https://metrics.awssolutionsbuilder.com/generic';
const SOLUTION_VERSION_PARAM = '/Solutions/SO0111/version';
const OLD_UUID_PARAM_NAME = '/Solutions/SO0111/anonymous_metrics_uuid';
const NEW_UUID_PARAM_NAME = '/Solutions/SO0111/metrics_uuid';

const DEFAULT_FAILURE_METRIC: FailureMetric = {
  status: 'FAILED',
  status_reason: 'PRE_PROCESSOR_FAILED',
  control_id: undefined,
  product_arn: undefined,
  region: undefined,
  error: undefined,
  truncatedRecordBody: undefined,
};

export function buildFailureMetric(
  error: unknown,
  truncatedRecord?: string,
  finding?: Record<any, any>,
): FailureMetric {
  const errorMessage = error instanceof Error ? error.message : String(error);
  if (!finding)
    return {
      ...DEFAULT_FAILURE_METRIC,
      truncatedRecordBody: truncatedRecord,
      error: errorMessage,
    };

  const asffResult = ASFFSchema.safeParse(finding);
  if (asffResult.success) {
    return {
      ...DEFAULT_FAILURE_METRIC,
      control_id: asffResult.data.Compliance.SecurityControlId,
      product_arn: asffResult.data.ProductArn,
      region: asffResult.data.Region,
      error: errorMessage,
      truncatedRecordBody: truncatedRecord,
    };
  }

  const ocsfResult = OCSFComplianceSchema.safeParse(finding);
  if (ocsfResult.success) {
    return {
      ...DEFAULT_FAILURE_METRIC,
      control_id: ocsfResult.data.compliance.control,
      product_arn: ocsfResult.data.metadata?.product?.uid,
      region: ocsfResult.data.cloud.region,
      error: errorMessage,
      truncatedRecordBody: truncatedRecord,
    };
  }

  return {
    ...DEFAULT_FAILURE_METRIC,
    truncatedRecordBody: truncatedRecord,
    error: errorMessage,
  };
}

export function buildFilteringMetric(
  filterResult: 'account_id_filter' | 'OUs_filter' | 'tags_filter' | 'none',
): Record<string, any> {
  return {
    finding_filtered_by_user: filterResult,
  };
}

export async function sendMetrics(metricsData: Record<string, any>): Promise<void> {
  try {
    const solutionUuid = await getSolutionUuid();
    const solutionVersion = await getSolutionVersion();

    const usageData: UsageData = {
      Solution: 'SO0111',
      UUID: solutionUuid,
      AccountId: AWS_ACCOUNT_ID,
      StackId: STACK_ID,
      TimeStamp: new Date().toISOString(),
      Data: metricsData,
      Version: solutionVersion,
    };
    logger.debug(`Sending metrics data ${JSON.stringify(usageData)}`);
    await postMetricsToApi(usageData);
  } catch (error) {
    logger.debug('Encountered error publishing Solutions Usage Metrics.', { error: error });
  }
}

export async function getSolutionVersion(): Promise<string | undefined> {
  return getCachedParameter(SOLUTION_VERSION_PARAM, logger);
}

async function tryGetAndDestroyDeprecatedUUIDParameter(): Promise<string | undefined> {
  const existingUUID = await getCachedParameter(OLD_UUID_PARAM_NAME, logger);
  try {
    if (existingUUID) {
      // delete the deprecated parameter
      const ssmClient = getSSMClient();
      await ssmClient.send(
        new DeleteParameterCommand({
          Name: OLD_UUID_PARAM_NAME,
        }),
      );
      logger.debug(`Deleted deprecated solution UUID parameter ${OLD_UUID_PARAM_NAME}`);
    }
  } catch (error) {
    logger.debug(
      `encountered an error deleting the deprecated solution parameter ${OLD_UUID_PARAM_NAME}. Continuing...`,
    );
  }

  return existingUUID;
}

export async function getSolutionUuid(): Promise<string | undefined> {
  try {
    const cachedUuid = await getCachedParameter(NEW_UUID_PARAM_NAME, logger);
    if (cachedUuid) {
      return cachedUuid;
    }

    // if we could not find the SSM parameter `NEW_UUID_PARAM_NAME `, look for the deprecated parameter before setting a new UUID value
    const existingUUID = await tryGetAndDestroyDeprecatedUUIDParameter();

    const uuid = existingUUID ?? randomUUID();
    const ssmClient = getSSMClient();
    await ssmClient.send(
      new PutParameterCommand({
        Name: NEW_UUID_PARAM_NAME,
        Value: uuid,
        Type: 'String',
      }),
    );

    logger.debug(`set UUID value for parameter ${NEW_UUID_PARAM_NAME}`);
    return uuid;
  } catch (error: any) {
    logger.debug('Error handling solution UUID', { error });
    return undefined;
  }
}

export function postMetricsToApi(requestData: UsageData): Promise<void> {
  return new Promise((resolve) => {
    try {
      const urlEncodedRequestData = encodeURIComponent(JSON.stringify(requestData));
      const postData = Buffer.from(urlEncodedRequestData, 'utf8');

      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': postData.length,
        },
      };

      const req = https.request(SOLUTIONS_METRICS_ENDPOINT, options, (res) => {
        res.on('data', () => {});
        res.on('end', () => resolve());
        res.on('error', (error) => {
          logger.debug('Response error sending metrics', { error: error.message });
          resolve();
        });
      });

      req.on('error', (error) => {
        logger.debug('Request error sending metrics', {
          error: error.message,
          code: (error as any).code,
        });
        resolve();
      });

      req.write(postData);
      req.end();
    } catch (error) {
      logger.debug('Exception in postMetricsToApi', { error: (error as Error).message });
      resolve();
    }
  });
}
