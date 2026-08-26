// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { validateJiraProjectKey, validateJiraIssueType } from '../jira-channel';
import { JiraProjectKey, JiraIssueType } from '../types';
import { InputValidationError } from '../notification-channel-errors';

describe('validateJiraProjectKey', () => {
  describe('GIVEN a valid project key', () => {
    it('WHEN the key is a standard uppercase string THEN it returns the key as a branded type', () => {
      // ARRANGE
      const keys = ['SEC', 'OPS_1', 'ABCDEFGHIJ', 'AB', 'A1', 'SEC_OPS'];

      // ACT & ASSERT
      for (const key of keys) {
        const result: JiraProjectKey = validateJiraProjectKey(key);
        expect(result).toBe(key);
      }
    });
  });

  describe('GIVEN a key not starting with an uppercase letter', () => {
    it('WHEN the key starts with a digit or underscore THEN it throws InputValidationError', () => {
      // ARRANGE
      const keys = ['1SEC', '_OPS', '0AB'];

      // ACT & ASSERT
      for (const key of keys) {
        expect(() => validateJiraProjectKey(key)).toThrow(InputValidationError);
      }
    });
  });

  describe('GIVEN a key with lowercase characters', () => {
    it('WHEN the key contains lowercase letters THEN it throws InputValidationError', () => {
      // ARRANGE
      const keys = ['Sec', 'ops', 'SECops', 'sEC'];

      // ACT & ASSERT
      for (const key of keys) {
        expect(() => validateJiraProjectKey(key)).toThrow(InputValidationError);
      }
    });
  });

  describe('GIVEN a single character key', () => {
    it('WHEN the key is only one character THEN it throws InputValidationError', () => {
      // ARRANGE
      const key = 'A';

      // ACT & ASSERT
      expect(() => validateJiraProjectKey(key)).toThrow(InputValidationError);
    });
  });

  describe('GIVEN a key exceeding 10 characters', () => {
    it('WHEN the key is 11 characters THEN it throws InputValidationError', () => {
      // ARRANGE
      const key = 'ABCDEFGHIJK';

      // ACT & ASSERT
      expect(() => validateJiraProjectKey(key)).toThrow(InputValidationError);
    });
  });

  describe('GIVEN a key with invalid characters', () => {
    it('WHEN the key contains hyphens, dots, or spaces THEN it throws InputValidationError', () => {
      // ARRANGE
      const keys = ['SEC-1', 'SEC.1', 'SEC 1', 'SE@C'];

      // ACT & ASSERT
      for (const key of keys) {
        expect(() => validateJiraProjectKey(key)).toThrow(InputValidationError);
      }
    });
  });
});

describe('validateJiraIssueType', () => {
  describe('GIVEN a valid issue type', () => {
    it('WHEN the issue type is a non-empty string THEN it returns the trimmed value as a branded type', () => {
      // ARRANGE
      const types = ['Bug', 'Task', 'Security', 'Story', 'Custom Type', '  Bug  ', ' Task\t'];

      // ACT & ASSERT
      for (const type of types) {
        const result: JiraIssueType = validateJiraIssueType(type);
        expect(result).toBe(type.trim());
      }
    });
  });

  describe('GIVEN an empty or whitespace-only issue type', () => {
    it('WHEN the issue type is empty or whitespace THEN it throws InputValidationError', () => {
      // ARRANGE
      const types = ['', '   ', '\t', '\n'];

      // ACT & ASSERT
      for (const type of types) {
        expect(() => validateJiraIssueType(type)).toThrow(InputValidationError);
      }
    });
  });
});
