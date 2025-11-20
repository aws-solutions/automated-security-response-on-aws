// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ASRParameters } from '../lib/constants/parameters';

describe('ASRParameters', () => {
  describe('TAG_FILTER_PATTERN', () => {
    const regex = ASRParameters.TAG_FILTER_PATTERN;

    describe('valid inputs', () => {
      it('should match "none"', () => {
        expect('none').toMatch(regex);
      });

      it('should match single tag key', () => {
        expect('Environment').toMatch(regex);
        expect('aws:cloudformation:stack-name').toMatch(regex);
        expect('Project_Name').toMatch(regex);
        expect('cost-center').toMatch(regex);
        expect('user@example.com').toMatch(regex);
        expect('key+value').toMatch(regex);
        expect('key=value').toMatch(regex);
      });

      it('should match comma-separated tag keys', () => {
        expect('Environment,Project').toMatch(regex);
        expect('Environment, Project').toMatch(regex);
        expect('Environment,  Project').toMatch(regex);
        expect('key1, key2, key3').toMatch(regex);
      });

      it('should match tag keys with special characters', () => {
        expect('aws:cloudformation:stack-name').toMatch(regex);
        expect('user@example.com').toMatch(regex);
        expect('key_with_underscore').toMatch(regex);
        expect('key.with.dots').toMatch(regex);
        expect('key:with:colons').toMatch(regex);
        expect('key/with/slashes').toMatch(regex);
        expect('key+with+plus').toMatch(regex);
        expect('key-with-dashes').toMatch(regex);
      });

      it('should match tag keys up to 128 characters', () => {
        const maxLengthKey = 'a'.repeat(128);
        expect(maxLengthKey).toMatch(regex);
        expect(`${maxLengthKey}, Environment`).toMatch(regex);
      });

      it('should match multiple tag keys with spaces after commas', () => {
        expect('tag1, tag2, tag3, tag4').toMatch(regex);
        expect('Environment,  Project,   Owner').toMatch(regex);
      });
    });

    describe('invalid inputs', () => {
      it('should not match empty string', () => {
        expect('').not.toMatch(regex);
      });

      it('should not match tag keys over 128 characters', () => {
        const tooLongKey = 'a'.repeat(129);
        expect(tooLongKey).not.toMatch(regex);
      });

      it('should not match tag keys with invalid characters', () => {
        expect('key with spaces').not.toMatch(regex);
        expect('key<with>brackets').not.toMatch(regex);
        expect('key[with]brackets').not.toMatch(regex);
        expect('key{with}braces').not.toMatch(regex);
        expect('key|with|pipe').not.toMatch(regex);
        expect('key\\with\\backslash').not.toMatch(regex);
      });

      it('should not match strings starting with comma', () => {
        expect(',Environment').not.toMatch(regex);
      });

      it('should not match strings ending with comma', () => {
        expect('Environment,').not.toMatch(regex);
      });

      it('should not match strings with consecutive commas', () => {
        expect('Environment,,Project').not.toMatch(regex);
      });
    });

    describe('ReDoS protection', () => {
      it('should not cause exponential backtracking with tabs and commas', () => {
        const start = Date.now();
        const maliciousInput = '\t,'.repeat(20) + '\t\t,'.repeat(20);

        // This should complete quickly (under 100ms) if ReDoS is fixed
        expect(maliciousInput).not.toMatch(regex);

        const duration = Date.now() - start;
        expect(duration).toBeLessThan(100);
      });

      it('should handle long strings with multiple commas efficiently', () => {
        const start = Date.now();
        // String ending with comma is invalid
        const input = 'a,'.repeat(100);

        expect(input).not.toMatch(regex);

        const duration = Date.now() - start;
        expect(duration).toBeLessThan(100);
      });

      it('should handle valid long comma-separated lists efficiently', () => {
        const start = Date.now();
        // Valid pattern with many items
        const validKeys = Array.from({ length: 50 }, (_, i) => `key${i}`).join(', ');

        expect(validKeys).toMatch(regex);

        const duration = Date.now() - start;
        expect(duration).toBeLessThan(100);
      });
    });
  });

  describe('ACCOUNT_FILTER_PATTERN', () => {
    const regex = ASRParameters.ACCOUNT_FILTER_PATTERN;

    it('should match "none"', () => {
      expect('none').toMatch(regex);
    });

    it('should match single 12-digit account ID', () => {
      expect('123456789012').toMatch(regex);
    });

    it('should match comma-separated account IDs', () => {
      expect('123456789012,234567890123').toMatch(regex);
      expect('123456789012, 234567890123').toMatch(regex);
      expect('123456789012,  234567890123').toMatch(regex);
    });

    it('should not match invalid account IDs', () => {
      expect('12345678901').not.toMatch(regex); // 11 digits
      expect('1234567890123').not.toMatch(regex); // 13 digits
      expect('abc123456789').not.toMatch(regex); // contains letters
    });
  });

  describe('DEFAULT_FILTER_MODE_PATTERN', () => {
    const regex = ASRParameters.DEFAULT_FILTER_MODE_PATTERN;

    it('should match valid filter modes', () => {
      expect('Include').toMatch(regex);
      expect('Exclude').toMatch(regex);
      expect('Disabled').toMatch(regex);
    });

    it('should not match invalid filter modes', () => {
      expect('include').not.toMatch(regex); // lowercase
      expect('INCLUDE').not.toMatch(regex); // uppercase
      expect('Enabled').not.toMatch(regex);
      expect('').not.toMatch(regex);
    });
  });
});
