// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** CSV column definition: display header + field name on the data object. */
export interface CsvColumn {
  readonly header: string;
  readonly field: string;
}

/**
 * Standard finding CSV columns — used by the WebUI findings export.
 *
 * Intentionally excludes the IaC template download columns: IaC remediation
 * code only makes sense for findings that were successfully remediated, so
 * those columns are remediation-only and live in getBatchCsvColumns
 * ('remediation') instead.
 */
export const FINDING_CSV_COLUMNS: readonly CsvColumn[] = [
  { header: 'Finding ID', field: 'findingId' },
  { header: 'Control ID', field: 'findingType' },
  { header: 'Title', field: 'findingDescription' },
  { header: 'Account', field: 'accountId' },
  { header: 'Region', field: 'region' },
  { header: 'Severity', field: 'severity' },
  { header: 'Resource Type', field: 'resourceTypeNormalized' },
  { header: 'Resource ID', field: 'resourceId' },
  { header: 'Remediation Status', field: 'remediationStatus' },
  { header: 'Detected At', field: 'creationTime' },
  { header: 'Security Hub Updated Time', field: 'securityHubUpdatedAtTime' },
  { header: 'Suppressed', field: 'suppressed' },
];

export function getBatchCsvColumns(notificationType: 'finding' | 'remediation'): readonly CsvColumn[] {
  const manualLinkHeader = notificationType === 'remediation' ? 'History URL' : 'Manual Remediation URL';
  const columns: CsvColumn[] = [
    { header: 'Config ID', field: 'configId' },
    { header: 'Config Name', field: 'configName' },
    { header: 'Event Type', field: 'eventType' },
    { header: 'Event ID', field: 'eventId' },
    { header: 'Control ID', field: 'controlId' },
    { header: 'Account ID', field: 'accountId' },
    { header: 'Region', field: 'region' },
    { header: 'Severity', field: 'severity' },
    { header: 'Resource Type', field: 'resourceType' },
    { header: 'Resource ID', field: 'resourceId' },
    { header: 'Title', field: 'title' },
    { header: 'Description', field: 'description' },
    { header: 'Detected At', field: 'detectedAt' },
    { header: 'Remediation Status', field: 'remediationStatus' },
    { header: 'Timestamp', field: 'timestamp' },
    { header: manualLinkHeader, field: 'manualRemediationUrl' },
    { header: 'Control Settings URL', field: 'controlSettingsUrl' },
  ];
  // Deadline columns only apply to finding notifications — remediation events are already resolved.
  if (notificationType === 'finding') {
    columns.push(
      { header: 'Remediation Deadline', field: 'remediationDeadlineDate' },
      // Cell holds a human-readable phrase (e.g. "5 days remaining", "399 days
      // overdue", "due today"), so "Deadline Status" reads correctly where the
      // older "Days Remaining" header would not.
      { header: 'Deadline Status', field: 'remediationDeadlineDaysRemaining' },
    );
  }
  // IaC template download links are remediation-only: they show how to codify a
  // fix that already happened, so they're populated only for successful
  // remediations. Finding notifications never have them, so omit the columns
  // entirely rather than emitting four always-empty cells.
  if (notificationType === 'remediation') {
    columns.push(
      { header: 'IaC CloudFormation (YAML)', field: 'iacCloudformationYaml' },
      { header: 'IaC CloudFormation (JSON)', field: 'iacCloudformationJson' },
      { header: 'IaC Terraform', field: 'iacTerraform' },
      { header: 'IaC CDK (TypeScript)', field: 'iacCdk' },
    );
  }
  return columns;
}

/** Characters that trigger formula execution in spreadsheet applications (OWASP CSV Injection). */
const FORMULA_TRIGGER_CHARS = '=+-@\t\r';

/** Escape a value for CSV (RFC 4180) and neutralize formula-injection vectors (OWASP CSV Injection). */
export function escapeCsvField(value: unknown): string {
  if (value === null || value === undefined) return '';
  // Narrow explicitly so no object/unknown reaches String() (which would emit
  // "[object Object]"): pass strings through, use the numeric/boolean toString,
  // and JSON-serialize everything else (objects/arrays) to preserve the data.
  let s: string;
  if (typeof value === 'string') {
    s = value;
  } else if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'boolean') {
    s = value.toString();
  } else {
    s = JSON.stringify(value) ?? '';
  }
  if (s.length > 0 && FORMULA_TRIGGER_CHARS.includes(s[0])) {
    s = `'${s}`;
  }
  return s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r') || s.includes('\t')
    ? `"${s.replaceAll('"', '""')}"`
    : s;
}

/** Convert an array of objects to CSV using the given column definitions. */
export function toCsv<T extends object>(items: T[], columns: readonly CsvColumn[]): string {
  const header = columns.map((c) => c.header).join(',');
  const rows = items.map((item) =>
    columns.map((c) => escapeCsvField((item as Record<string, unknown>)[c.field])).join(','),
  );
  return [header, ...rows].join('\n');
}
