// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Extracts control ID from finding ID
 * @param findingId - The Security Hub finding ID
 * @returns The extracted control ID or undefined if not found
 */
export function getControlIdFromFindingId(findingId: string): string | undefined {
  // finding id structure depends on consolidation settings
  // https://aws.amazon.com/blogs/security/consolidating-controls-in-security-hub-the-new-controls-view-and-consolidated-findings/
  const UNCONSOLIDATED_FINDING_ID_REGEX =
    /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:subscription\/(.+)\/finding\/.+$/g;
  const CONSOLIDATED_FINDING_ID_REGEX =
    /^arn:(?:aws|aws-cn|aws-us-gov):securityhub:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:(.+)\/finding\/.+$/g;

  const unconsolidatedMatch = UNCONSOLIDATED_FINDING_ID_REGEX.exec(findingId);
  if (unconsolidatedMatch) return unconsolidatedMatch[1]; // example: 'aws-foundational-security-best-practices/v/1.0.0/S3.1'

  const consolidatedMatch = CONSOLIDATED_FINDING_ID_REGEX.exec(findingId);
  if (consolidatedMatch) return consolidatedMatch[1]; // example: 'security-control/Lambda.3'

  return undefined;
}

/**
 * Sanitizes control ID to ensure it matches expected format
 * @param controlId - The control ID to sanitize
 * @returns The sanitized control ID
 */
export function sanitizeControlId(controlId: string): string {
  const NON_ALPHANUMERIC_OR_DOT_SLASH = /[^a-zA-Z0-9/.-]/g;
  return controlId.replace(NON_ALPHANUMERIC_OR_DOT_SLASH, '');
}

/**
 * Gets the appropriate console host based on AWS partition
 * @param partition - AWS partition (aws, aws-us-gov, aws-cn)
 * @returns Console host URL
 */
function getConsoleHost(partition: string): string {
  const consoleHosts = {
    aws: 'console.aws.amazon.com',
    'aws-us-gov': 'console.amazonaws-us-gov.com',
    'aws-cn': 'console.amazonaws.cn',
  };

  return consoleHosts[partition as keyof typeof consoleHosts] || consoleHosts.aws;
}

/**
 * Generates Security Hub finding console URL. If Security Hub V2 is enabled in the current account, this finding links to
 * the Security Hub console. Otherwise, it links to Security Hub CSPM.
 * @param findingId - The Security Hub finding ID
 * @param region - AWS region (optional, defaults to AWS_REGION env var) - Since the solution must be deployed in the Security Hub aggregation region, all findings should be available in the region where this Lambda function exists, meaning you likely do not want to pass a value for this parameter unless you require a region-specific console link.
 * @param partition - AWS partition (optional, defaults to AWS_PARTITION env var)
 * @returns Console URL for the Security Hub finding
 */
export function getSecurityHubConsoleUrl(findingId: string, region?: string, partition?: string): string {
  const securityHubV2Enabled = process.env.SECURITY_HUB_V2_ENABLED?.toLowerCase() === 'true';
  const awsRegion = region || process.env.AWS_REGION || 'us-east-1';
  const awsPartition = partition || process.env.AWS_PARTITION || 'aws';

  const host = getConsoleHost(awsPartition);

  const urlPattern =
    process.env.CONSOLE_URL_PATTERN ||
    (securityHubV2Enabled
      ? `/securityhub/v2/home?region=${awsRegion}#/findings?search=finding_info.uid%3D%255Coperator%255C%253AEQUALS%255C%253A${encodeURIComponent(findingId)}`
      : `/securityhub/home?region=${awsRegion}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A${encodeURIComponent(findingId)}`);
  return `https://${awsRegion}.${host}${urlPattern}`;
}

/**
 * Generates Step Functions execution console URL
 * @param executionId - The Step Functions execution ID/ARN
 * @param region - AWS region (optional, defaults to AWS_REGION env var)
 * @param partition - AWS partition (optional, defaults to AWS_PARTITION env var)
 * @returns Console URL for the Step Functions execution
 */
export function getStepFunctionsConsoleUrl(executionId?: string, region?: string, partition?: string): string {
  if (!executionId) {
    return '';
  }

  const awsRegion = region || process.env.AWS_REGION || 'us-east-1';
  const awsPartition = partition || process.env.AWS_PARTITION || 'aws';

  const host = getConsoleHost(awsPartition);

  const urlPattern =
    process.env.EXECUTION_CONSOLE_URL_PATTERN ||
    `/states/home?region=${awsRegion}#/v2/executions/details/${encodeURIComponent(executionId)}`;

  return `https://${awsRegion}.${host}${urlPattern}`;
}
