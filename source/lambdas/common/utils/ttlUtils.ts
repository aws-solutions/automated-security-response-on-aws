// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Generic function to calculate a TTL (Time To Live) timestamp for DynamoDB item expiration.
 *
 * TTL is used to automatically delete items from DynamoDB after a specified time period.
 * This function adds a configurable number of days to a given date and returns the result
 * as a Unix timestamp in seconds, which is the format required by DynamoDB's TTL feature.
 *
 * @param lastUpdatedTime - ISO 8601 date string (e.g., "2023-12-01T10:30:00Z") or any valid
 *                          JavaScript Date constructor input. This is the base date from which
 *                          the TTL expiration time is calculated.
 * @param envVarName - Name of the environment variable to read TTL days from
 * @param defaultDays - Default number of days if environment variable is not set or invalid
 * @param ttlDays - Optional override for the number of days to add. If provided, takes precedence
 *                  over environment variable and default.
 * @returns Unix timestamp in seconds representing when the DynamoDB item should expire
 */
function calculateTtlTimestampGeneric(
  lastUpdatedTime: string,
  envVarName: string,
  defaultDays: number,
  ttlDays?: number,
): number {
  const days = ttlDays ?? parseInt(process.env[envVarName] || defaultDays.toString(), 10);

  // Ensure days is a valid positive number, fallback to default if invalid
  const validDays = isNaN(days) || days <= 0 ? defaultDays : days;

  const updatedAtDate = new Date(lastUpdatedTime);
  const ttlDate = new Date(updatedAtDate.getTime() + validDays * 24 * 60 * 60 * 1000);

  // DynamoDB TTL expects Unix timestamp in seconds
  return Math.floor(ttlDate.getTime() / 1000);
}

export function calculateTtlTimestamp(lastUpdatedTime: string, ttlDays?: number): number {
  return calculateTtlTimestampGeneric(lastUpdatedTime, 'FINDINGS_TTL_DAYS', 8, ttlDays);
}

export function calculateHistoryTtlTimestamp(lastUpdatedTime: string, ttlDays?: number): number {
  return calculateTtlTimestampGeneric(lastUpdatedTime, 'HISTORY_TTL_DAYS', 365, ttlDays);
}
