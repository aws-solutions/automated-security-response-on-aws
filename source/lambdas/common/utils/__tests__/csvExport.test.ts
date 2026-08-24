// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { escapeCsvField, getBatchCsvColumns, toCsv } from '../csvExport';

describe('getBatchCsvColumns', () => {
  const headers = (type: 'finding' | 'remediation') => getBatchCsvColumns(type).map((c) => c.header);

  it('uses "Manual Remediation URL" and appends deadline columns for finding notifications', () => {
    const cols = headers('finding');
    expect(cols).toContain('Manual Remediation URL');
    expect(cols).not.toContain('History URL');
    // Deadline columns apply only to finding notifications.
    expect(cols).toContain('Remediation Deadline');
    expect(cols).toContain('Deadline Status');
    // IaC columns are remediation-only.
    expect(cols).not.toContain('IaC Terraform');
  });

  it('uses "History URL" and appends IaC columns for remediation notifications', () => {
    const cols = headers('remediation');
    expect(cols).toContain('History URL');
    expect(cols).not.toContain('Manual Remediation URL');
    // IaC template links are remediation-only.
    expect(cols).toEqual(
      expect.arrayContaining([
        'IaC CloudFormation (YAML)',
        'IaC CloudFormation (JSON)',
        'IaC Terraform',
        'IaC CDK (TypeScript)',
      ]),
    );
    // Deadline columns must be absent for remediation events.
    expect(cols).not.toContain('Remediation Deadline');
    expect(cols).not.toContain('Deadline Status');
  });

  it('shares the common column set across both notification types', () => {
    const finding = headers('finding');
    const remediation = headers('remediation');
    for (const shared of ['Config ID', 'Event ID', 'Control ID', 'Account ID', 'Region', 'Severity']) {
      expect(finding).toContain(shared);
      expect(remediation).toContain(shared);
    }
  });
});

describe('escapeCsvField', () => {
  it('returns empty string for null and undefined', () => {
    expect(escapeCsvField(null)).toBe('');
    expect(escapeCsvField(undefined)).toBe('');
  });

  it('returns plain values unchanged', () => {
    expect(escapeCsvField('hello')).toBe('hello');
    expect(escapeCsvField(42)).toBe('42');
  });

  it('quotes values containing commas, quotes, newlines, CR, or tabs', () => {
    expect(escapeCsvField('a,b')).toBe('"a,b"');
    expect(escapeCsvField('a"b')).toBe('"a""b"');
    expect(escapeCsvField('a\nb')).toBe('"a\nb"');
    // CR/tab also force quoting per RFC 4180; without this, a bare CR inside
    // an unquoted field is interpreted as a record separator and breaks
    // downstream parsers (Excel, csv libraries).
    expect(escapeCsvField('a\rb')).toBe('"a\rb"');
    expect(escapeCsvField('a\tb')).toBe('"a\tb"');
  });

  describe('formula-injection guard', () => {
    it.each([
      ['=SUM(A1:A10)', "'=SUM(A1:A10)"],
      ['+1+1', "'+1+1"],
      ['-2', "'-2"],
      ['@cmd', "'@cmd"],
    ])('prefixes leading "%s" with apostrophe to neutralize formula', (input, expected) => {
      expect(escapeCsvField(input)).toBe(expected);
    });

    // Leading tab/CR also trigger the formula-injection guard, but the value
    // ends up wrapped in quotes too because tabs/CRs trigger the row-quoting
    // predicate (RFC 4180). The apostrophe still neutralizes the formula.
    it.each([
      ['\tleading-tab', '"\'\tleading-tab"'],
      ['\rleading-cr', '"\'\rleading-cr"'],
    ])('prefixes apostrophe AND quotes "%s" (leading tab/CR)', (input, expected) => {
      expect(escapeCsvField(input)).toBe(expected);
    });

    it('does not prefix when formula char is in the middle', () => {
      expect(escapeCsvField('a=b')).toBe('a=b');
    });
  });
});

describe('toCsv', () => {
  it('emits header and quotes formula-injection cells', () => {
    const rows = [{ name: '=cmd', value: 'ok' }];
    const csv = toCsv(rows, [
      { header: 'Name', field: 'name' },
      { header: 'Value', field: 'value' },
    ]);
    expect(csv).toBe(['Name,Value', "'=cmd,ok"].join('\n'));
  });
});
