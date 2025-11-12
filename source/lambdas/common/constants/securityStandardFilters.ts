// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { GetFindingsCommandInput } from '@aws-sdk/client-securityhub';
import { DynamoDBDocumentClient, ScanCommand } from '@aws-sdk/lib-dynamodb';

/**
 * Security Standard identifiers used by AWS Security Hub
 * These correspond to the GeneratorId prefixes in Security Hub findings
 */
export const SECURITY_STANDARD_IDENTIFIERS = {
  AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES: 'aws-foundational-security-best-practices',
  CIS_AWS_FOUNDATIONS_BENCHMARK: 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark',
  SECURITY_CONTROL: 'security-control',
  PCI_DSS: 'pci-dss',
  NIST_800_53: 'nist-800-53',
} as const;

export const STANDARDS_WITH_REMEDIATIONS = [
  SECURITY_STANDARD_IDENTIFIERS.AWS_FOUNDATIONAL_SECURITY_BEST_PRACTICES,
  SECURITY_STANDARD_IDENTIFIERS.CIS_AWS_FOUNDATIONS_BENCHMARK,
  SECURITY_STANDARD_IDENTIFIERS.SECURITY_CONTROL,
  SECURITY_STANDARD_IDENTIFIERS.PCI_DSS,
  SECURITY_STANDARD_IDENTIFIERS.NIST_800_53,
] as const;

export function getOptimizedFindingFilters(): NonNullable<GetFindingsCommandInput['Filters']> {
  return {
    // Only active findings
    RecordState: [
      {
        Value: 'ACTIVE',
        Comparison: 'EQUALS',
      },
    ],
    // Exclude findings that are already compliant or not applicable
    ComplianceStatus: [
      {
        Value: 'PASSED',
        Comparison: 'NOT_EQUALS',
      },
      {
        Value: 'NOT_AVAILABLE',
        Comparison: 'NOT_EQUALS',
      },
    ],
    // Only Security Hub products
    ProductArn: [
      {
        Value: 'arn:aws:securityhub',
        Comparison: 'PREFIX',
      },
    ],
    GeneratorId: STANDARDS_WITH_REMEDIATIONS.map((standard) => ({
      Value: standard,
      Comparison: 'PREFIX',
    })),
  };
}

/**
 * Enhanced version that fetches controlIds from REMEDIATION_CONFIG_TABLE and applies them as filters
 * @param controlIds Supported control ids
 * @returns Promise with optimized filters including controlId filters
 */
export async function getOptimizedFindingFiltersByControlId(
  controlIds: string[],
): Promise<NonNullable<GetFindingsCommandInput['Filters']>> {
  try {
    const baseFilters = getOptimizedFindingFilters();

    if (controlIds.length > 0) {
      return {
        ...baseFilters,
        ComplianceSecurityControlId: controlIds.map((controlId) => ({
          Value: controlId,
          Comparison: 'EQUALS',
        })),
      };
    }

    return baseFilters;
  } catch (error) {
    console.warn('Failed to process controlIds, returning empty filters:', error);
    return {};
  }
}

/**
 * Utility function to split an array into chunks of specified size
 * @param array The array to chunk
 * @param chunkSize Maximum size of each chunk
 * @returns Array of chunks
 */
export function chunkArray<T>(array: T[], chunkSize: number): T[][] {
  if (chunkSize <= 0) {
    return [];
  }

  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
}

/**
 * Fetches all supported controlIds from the remediation configuration table
 * @param dynamoClient DynamoDB document client
 * @param tableName Remediation config table name
 * @returns Array of controlIds that have remediation support
 */
export async function getSupportedControlIds(
  dynamoClient: DynamoDBDocumentClient,
  tableName: string,
): Promise<string[]> {
  const controlIds: string[] = [];
  let lastEvaluatedKey: Record<string, any> | undefined;

  do {
    const command = new ScanCommand({
      TableName: tableName,
      ProjectionExpression: 'controlId',
      ExclusiveStartKey: lastEvaluatedKey,
    });

    const result = await dynamoClient.send(command);

    if (result.Items) {
      const batchControlIds = result.Items.map((item) => item.controlId).filter(
        (controlId): controlId is string => typeof controlId === 'string',
      );

      controlIds.push(...batchControlIds);
    }

    lastEvaluatedKey = result.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  return controlIds;
}

/**
 * Fetches supported controlIds in chunks to avoid API limitations
 * @param dynamoClient DynamoDB document client
 * @param tableName Remediation config table name
 * @param chunkSize Maximum number of controlIds per chunk (default: 20)
 * @returns Array of controlId chunks
 */
export async function getSupportedControlIdsInChunks(
  dynamoClient: DynamoDBDocumentClient,
  tableName: string,
  chunkSize: number = 20,
): Promise<string[][]> {
  const controlIds = await getSupportedControlIds(dynamoClient, tableName);
  return chunkArray(controlIds, chunkSize);
}

/**
 * Enhanced version that creates optimized input with controlId-based filtering
 * @param filters The filters to apply to the GetFindings request
 * @param nextToken Pagination token
 * @param maxResults Maximum number of results
 * @returns Promise with optimized GetFindingsCommand input including controlId filters
 */
export async function createOptimizedGetFindingsInputByControlId(
  filters: NonNullable<GetFindingsCommandInput['Filters']>,
  nextToken?: string,
  maxResults: number = 100,
): Promise<GetFindingsCommandInput> {
  return {
    Filters: filters,
    SortCriteria: [
      {
        Field: 'SeverityNormalized',
        SortOrder: 'desc', // Highest severity first (CRITICAL=90, HIGH=70, MEDIUM=40, LOW=1)
      },
      {
        Field: 'UpdatedAt',
        SortOrder: 'desc', // Most recently updated first as secondary sort
      },
    ],
    MaxResults: maxResults,
    NextToken: nextToken,
  };
}
