// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest';

import {
  parseAccountIds,
  validateAccountIds,
  validateEmail,
  validateAccountId,
  validateOrganizationalUnitId,
  validateArnPattern,
  parseEmails,
  isValidInternalPath,
} from '../../utils/validation.ts';

describe('parseAccountIds', () => {
  it('splits comma-separated IDs and trims whitespace', () => {
    expect(parseAccountIds(' 111111111111 , 222222222222 ')).toEqual(['111111111111', '222222222222']);
  });

  it('filters out empty segments from trailing commas', () => {
    expect(parseAccountIds('111111111111,,,')).toEqual(['111111111111']);
  });

  it('returns an empty array for blank input', () => {
    expect(parseAccountIds('  ')).toEqual([]);
  });
});

describe('validateAccountIds', () => {
  it('returns null for valid comma-separated 12-digit IDs', () => {
    expect(validateAccountIds('111111111111,222222222222')).toBeNull();
  });

  it('returns an error when input is empty', () => {
    expect(validateAccountIds('')).toBe('Please enter at least one account ID.');
  });

  it('returns an error when input is only whitespace/commas', () => {
    expect(validateAccountIds(' , , ')).toBe('Please enter at least one account ID.');
  });

  it('returns an error when any ID is not 12 digits', () => {
    expect(validateAccountIds('12345')).toBe(
      'Invalid account IDs. Each account ID must be exactly 12 digits separated by commas.',
    );
  });

  it('returns an error when an ID contains non-digit characters', () => {
    expect(validateAccountIds('12345678901a')).toBe(
      'Invalid account IDs. Each account ID must be exactly 12 digits separated by commas.',
    );
  });
});

describe('validateEmail', () => {
  it('returns null for a valid email', () => {
    expect(validateEmail('user@example.com')).toBeNull();
  });

  it('returns null for empty/whitespace input', () => {
    expect(validateEmail('')).toBeNull();
    expect(validateEmail('   ')).toBeNull();
  });

  it('returns an error for an invalid email', () => {
    expect(validateEmail('not-an-email')).toBe('Please enter a valid email address');
  });

  it('trims whitespace before validating', () => {
    expect(validateEmail('  user@example.com  ')).toBeNull();
  });
});

describe('validateAccountId', () => {
  it('returns null for a valid 12-digit account ID', () => {
    expect(validateAccountId('123456789012')).toBeNull();
  });

  it('rejects IDs shorter than 12 digits', () => {
    expect(validateAccountId('12345')).toBe('Account ID must be exactly 12 digits.');
  });

  it('rejects IDs longer than 12 digits', () => {
    expect(validateAccountId('1234567890123')).toBe('Account ID must be exactly 12 digits.');
  });

  it('rejects IDs with non-digit characters', () => {
    expect(validateAccountId('12345678901a')).toBe('Account ID must be exactly 12 digits.');
  });

  it('rejects an empty string', () => {
    expect(validateAccountId('')).toBe('Account ID must be exactly 12 digits.');
  });
});

describe('validateOrganizationalUnitId', () => {
  it('returns null for a valid OU ID', () => {
    expect(validateOrganizationalUnitId('ou-ab12-12345678')).toBeNull();
  });

  it('rejects an OU ID missing the ou- prefix', () => {
    expect(validateOrganizationalUnitId('ab12-12345678')).toBe('OU ID must match pattern ou-xxxx-xxxxxxxx.');
  });

  it('rejects an OU ID with uppercase letters', () => {
    expect(validateOrganizationalUnitId('ou-AB12-12345678')).toBe('OU ID must match pattern ou-xxxx-xxxxxxxx.');
  });

  it('rejects an OU ID with a too-short first segment', () => {
    expect(validateOrganizationalUnitId('ou-ab-12345678')).toBe('OU ID must match pattern ou-xxxx-xxxxxxxx.');
  });

  it('rejects an OU ID with a too-short second segment', () => {
    expect(validateOrganizationalUnitId('ou-ab12-1234')).toBe('OU ID must match pattern ou-xxxx-xxxxxxxx.');
  });

  it('rejects an empty string', () => {
    expect(validateOrganizationalUnitId('')).toBe('OU ID must match pattern ou-xxxx-xxxxxxxx.');
  });
});

describe('validateArnPattern', () => {
  it('returns null for a valid ARN', () => {
    expect(validateArnPattern('arn:aws:s3:::my-bucket')).toBeNull();
  });

  it('returns null for an ARN with wildcard partitions', () => {
    expect(validateArnPattern('arn:*:ec2:us-east-1:123456789012:instance/*')).toBeNull();
  });

  it('returns null for an ARN with empty optional segments', () => {
    expect(validateArnPattern('arn:aws:s3:::my-bucket/key')).toBeNull();
  });

  it('rejects a string missing the arn: prefix', () => {
    expect(validateArnPattern('not:an:arn:at:all:nope')).toBe(
      'ARN must follow arn:partition:service:region:account-id:resource format.',
    );
  });

  it('rejects an ARN with too few colon-separated segments', () => {
    expect(validateArnPattern('arn:aws:s3')).toBe(
      'ARN must follow arn:partition:service:region:account-id:resource format.',
    );
  });

  it('rejects an ARN with an empty resource segment', () => {
    expect(validateArnPattern('arn:aws:s3:::')).toBe(
      'ARN must follow arn:partition:service:region:account-id:resource format.',
    );
  });

  it('rejects an empty string', () => {
    expect(validateArnPattern('')).toBe('ARN must follow arn:partition:service:region:account-id:resource format.');
  });
});

describe('parseEmails', () => {
  it('splits comma-separated emails and trims whitespace', () => {
    expect(parseEmails(' a@b.com , c@d.com ')).toEqual(['a@b.com', 'c@d.com']);
  });

  it('filters out empty segments', () => {
    expect(parseEmails('a@b.com,,,')).toEqual(['a@b.com']);
  });

  it('returns an empty array for blank input', () => {
    expect(parseEmails('  ')).toEqual([]);
  });
});

describe('isValidInternalPath', () => {
  describe('valid internal paths', () => {
    it.each([
      ['/', 'root path'],
      ['/controls', 'simple path'],
      ['/controls/S3.1', 'nested path'],
      ['/controls?controlId=S3.1', 'path with query string'],
      ['/controls?controlId=S3.1&tab=details', 'path with multiple query params'],
      ['/path#section', 'path with hash fragment'],
      ['/path?query=value#section', 'path with query and hash'],
      ['/users/123/edit', 'path with numeric segments'],
      ['/a/b/c/d/e', 'deeply nested path'],
    ])('returns true for %s (%s)', (path) => {
      expect(isValidInternalPath(path)).toBe(true);
    });
  });

  describe('protocol-relative URLs (open redirect attack vector)', () => {
    it.each([
      ['//malicious-site.com', 'basic protocol-relative URL'],
      ['//malicious-site.com/path', 'protocol-relative URL with path'],
      ['//evil.com?redirect=/', 'protocol-relative URL with query'],
      ['///triple-slash.com', 'triple slash URL'],
    ])('returns false for %s (%s)', (path) => {
      expect(isValidInternalPath(path)).toBe(false);
    });
  });

  describe('absolute URLs with protocols', () => {
    it.each([
      ['https://malicious-site.com', 'HTTPS URL'],
      ['http://malicious-site.com', 'HTTP URL'],
      ['javascript:alert(1)', 'javascript protocol'],
      ['data:text/html,<script>alert(1)</script>', 'data URL'],
      ['ftp://files.example.com', 'FTP URL'],
      ['file:///etc/passwd', 'file protocol'],
    ])('returns false for %s (%s)', (path) => {
      expect(isValidInternalPath(path)).toBe(false);
    });
  });

  describe('paths not starting with /', () => {
    it.each([
      ['controls', 'relative path without leading slash'],
      ['../parent', 'parent directory traversal'],
      ['./current', 'current directory reference'],
      ['malicious-site.com/path', 'domain without protocol'],
    ])('returns false for %s (%s)', (path) => {
      expect(isValidInternalPath(path)).toBe(false);
    });
  });

  describe('Windows-style paths (backslash)', () => {
    it.each([['\\\\server\\share', 'UNC path']])('returns false for %s (%s)', (path) => {
      expect(isValidInternalPath(path)).toBe(false);
    });

    it.each([
      ['/path\\to\\file', 'mixed slashes - normalized by URL constructor'],
      ['/controls\\..\\admin', 'backslash traversal - normalized by URL constructor'],
    ])('returns true for %s (%s) - URL constructor normalizes backslashes', (path) => {
      expect(isValidInternalPath(path)).toBe(true);
    });
  });

  describe('null, undefined, and empty values', () => {
    it('returns false for null', () => {
      expect(isValidInternalPath(null)).toBe(false);
    });

    it('returns false for undefined', () => {
      expect(isValidInternalPath(undefined)).toBe(false);
    });

    it('returns false for empty string', () => {
      expect(isValidInternalPath('')).toBe(false);
    });

    it('returns false for whitespace-only string', () => {
      expect(isValidInternalPath('   ')).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('returns true for path with colon in query string', () => {
      expect(isValidInternalPath('/path?time=10:30')).toBe(true);
    });

    it('returns true for encoded characters that remain safe', () => {
      expect(isValidInternalPath('/path%20with%20spaces')).toBe(true);
    });
  });
});
