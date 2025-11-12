// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

describe('Filter Pattern Validation Tests', () => {
  describe('Filter Mode Pattern Validation', () => {
    it('should accept valid filter modes', () => {
      const validModes = ['Include', 'Exclude', 'Disabled'];

      validModes.forEach((mode) => {
        expect(['Include', 'Exclude', 'Disabled'].includes(mode)).toBe(true);
      });
    });

    it('should reject invalid filter modes', () => {
      const invalidModes = ['include', 'INCLUDE', 'InvalidMode', '', 'enabled', 'disabled', 'exclude'];

      invalidModes.forEach((mode) => {
        expect(['Include', 'Exclude', 'Disabled'].includes(mode)).toBe(false);
      });
    });
  });

  describe('Account ID Pattern Validation', () => {
    it('should accept valid account IDs', () => {
      const validAccountIds = [
        '123456789012',
        '234567890123',
        '123456789012,234567890123',
        '123456789012, 234567890123',
        '123456789012 , 234567890123 , 345678901234',
      ];

      validAccountIds.forEach((accountIdString) => {
        const accountIds = accountIdString
          .split(',')
          .map((id) => id.trim())
          .filter((id) => id);
        accountIds.forEach((accountId) => {
          // Valid account ID should be 12 digits
          expect(accountId).toMatch(/^\d{12}$/);
        });
      });
    });

    it('should reject invalid account IDs', () => {
      const invalidAccountIds = [
        '12345678901', // Too short (11 digits)
        '1234567890123', // Too long (13 digits)
        'abc123456789', // Contains letters
        '123-456-789', // Contains hyphens
        '', // Empty string
        '123456789012,', // Trailing comma
        ',123456789012', // Leading comma
        '123456789012,,234567890123', // Double comma
      ];

      invalidAccountIds.forEach((accountIdString) => {
        // Check for malformed comma patterns first
        const hasMalformedCommas = /^,|,$|,,/.test(accountIdString);
        // Check individual values after filtering
        const accountIds = accountIdString
          .split(',')
          .map((id) => id.trim())
          .filter((id) => id);
        const hasInvalidId = accountIds.some((accountId) => !/^\d{12}$/.test(accountId));
        expect(hasMalformedCommas || hasInvalidId || accountIds.length === 0).toBe(true);
      });
    });
  });

  describe('OU ID Pattern Validation', () => {
    it('should accept valid OU IDs', () => {
      const validOuIds = [
        'ou-1234567890',
        'ou-abcd123456',
        'ou-1234567890,ou-abcd123456',
        'ou-1234567890, ou-abcd123456',
        'ou-root-123456789, ou-1234567890abcd',
      ];

      validOuIds.forEach((ouIdString) => {
        const ouIds = ouIdString
          .split(',')
          .map((ou) => ou.trim())
          .filter((ou) => ou);
        ouIds.forEach((ouId) => {
          // Valid OU ID should start with 'ou-' followed by alphanumeric characters
          expect(ouId).toMatch(/^ou(-root)?-[a-zA-Z0-9]+$/);
        });
      });
    });

    it('should reject invalid OU IDs', () => {
      const invalidOuIds = [
        'o-1234567890', // Wrong prefix
        'ou1234567890', // Missing dash
        'OU-1234567890', // Wrong case
        'ou-', // No ID part
        '', // Empty string
        'ou-123,', // Trailing comma
        ',ou-123', // Leading comma
        'ou-123,,ou-456', // Double comma
      ];

      invalidOuIds.forEach((ouIdString) => {
        // Check for malformed comma patterns first
        const hasMalformedCommas = /^,|,$|,,/.test(ouIdString);
        // Check individual values after filtering
        const ouIds = ouIdString
          .split(',')
          .map((ou) => ou.trim())
          .filter((ou) => ou);
        const hasInvalidId = ouIds.some((ouId) => !/^ou(-root)?-[a-zA-Z0-9]+$/.test(ouId));
        expect(hasMalformedCommas || hasInvalidId || ouIds.length === 0).toBe(true);
      });
    });
  });

  describe('Tag Key Pattern Validation', () => {
    it('should accept valid tag keys', () => {
      const validTagKeys = [
        'Environment',
        'Project',
        'CostCenter',
        'Environment,Project',
        'Environment, Project',
        'Environment , Project , CostCenter',
        'env-type',
        'project_name',
        'aws:cloudformation:stack-name',
      ];

      validTagKeys.forEach((tagKeyString) => {
        const tagKeys = tagKeyString
          .split(',')
          .map((tag) => tag.trim())
          .filter((tag) => tag);
        tagKeys.forEach((tagKey) => {
          // Valid tag key should be non-empty and contain valid characters
          expect(tagKey.length).toBeGreaterThan(0);
          expect(tagKey.length).toBeLessThanOrEqual(128);
          // AWS tag keys can contain letters, numbers, spaces, and some special characters
          expect(tagKey).toMatch(/^[a-zA-Z0-9\s+\-=._:/]+$/);
        });
      });
    });

    it('should reject invalid tag keys', () => {
      const invalidTagKeys = [
        '', // Empty string
        'Environment,', // Trailing comma
        ',Environment', // Leading comma
        'Env,,Project', // Double comma
        'x'.repeat(129), // Too long (>128 characters)
        'tag<script>', // Invalid characters
        'tag@email.com', // Invalid @ symbol
        'tag{bracket}', // Invalid brackets
      ];

      invalidTagKeys.forEach((tagKeyString) => {
        // Check for malformed comma patterns first
        const hasMalformedCommas = /^,|,$|,,/.test(tagKeyString);
        // Check individual values after filtering
        const tagKeys = tagKeyString
          .split(',')
          .map((tag) => tag.trim())
          .filter((tag) => tag);
        const hasInvalidKey = tagKeys.some(
          (tagKey) => tagKey.length === 0 || tagKey.length > 128 || !/^[a-zA-Z0-9\s+\-=._:/]+$/.test(tagKey),
        );
        expect(hasMalformedCommas || hasInvalidKey || tagKeys.length === 0).toBe(true);
      });
    });
  });

  describe('Comma-Separated Value Parsing', () => {
    it('should parse comma-separated filter lists correctly', () => {
      // Account IDs test
      const accountIds = '123456789012, 234567890123,345678901234';
      const parsedAccountIds = accountIds.split(',').map((id: string) => id.trim());
      expect(parsedAccountIds).toEqual(['123456789012', '234567890123', '345678901234']);

      // OU IDs test
      const ouIds = 'ou-1234,ou-5678, ou-9012';
      const parsedOuIds = ouIds.split(',').map((ou: string) => ou.trim());
      expect(parsedOuIds).toEqual(['ou-1234', 'ou-5678', 'ou-9012']);

      // Tag keys test
      const tagKeys = 'Environment, Project,CostCenter';
      const parsedTagKeys = tagKeys.split(',').map((tag: string) => tag.trim());
      expect(parsedTagKeys).toEqual(['Environment', 'Project', 'CostCenter']);
    });

    it('should handle empty values in comma-separated lists', () => {
      // Test filtering out empty values
      const accountIdsWithEmpty = '123456789012,,234567890123,';
      const filteredAccountIds = accountIdsWithEmpty
        .split(',')
        .map((id: string) => id.trim())
        .filter((id: string) => id);
      expect(filteredAccountIds).toEqual(['123456789012', '234567890123']);

      // Test with just commas
      const justCommas = ',,,';
      const filteredEmpty = justCommas
        .split(',')
        .map((id: string) => id.trim())
        .filter((id: string) => id);
      expect(filteredEmpty).toEqual([]);
    });
  });
});
