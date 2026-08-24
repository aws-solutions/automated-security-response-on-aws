// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { checkJiraInstanceUrl } from '@asr/data-models';

describe('checkJiraInstanceUrl', () => {
  describe('GIVEN a valid HTTPS URL', () => {
    it('WHEN the URL is a standard Atlassian Cloud instance THEN it returns null', () => {
      // ARRANGE
      const url = 'https://company.atlassian.net';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toBeNull();
    });

    it('WHEN the URL is a self-hosted JIRA instance THEN it returns null', () => {
      // ARRANGE
      const url = 'https://jira.example.com';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toBeNull();
    });

    it('WHEN the URL has a path segment THEN it returns null', () => {
      // ARRANGE
      const url = 'https://jira.example.com/context';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toBeNull();
    });
  });

  describe('GIVEN a non-HTTPS URL', () => {
    it('WHEN the URL uses HTTP THEN it returns an error mentioning HTTPS', () => {
      // ARRANGE
      const url = 'http://jira.example.com';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toMatch(/HTTPS/);
    });
  });

  describe('GIVEN a URL exceeding 2,048 characters', () => {
    it('WHEN validated THEN it returns an error mentioning the length limit', () => {
      // ARRANGE
      const url = 'https://jira.example.com/' + 'a'.repeat(2048);

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toMatch(/2,048/);
    });
  });

  describe('GIVEN a URL with query parameters', () => {
    it('WHEN validated THEN it returns an error mentioning query parameters', () => {
      // ARRANGE
      const url = 'https://jira.example.com?foo=bar';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toMatch(/query parameters/);
    });
  });

  describe('GIVEN a URL with fragments', () => {
    it('WHEN validated THEN it returns an error mentioning fragment', () => {
      // ARRANGE
      const url = 'https://jira.example.com#section';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toMatch(/fragment/);
    });
  });

  describe('GIVEN a URL with a trailing slash', () => {
    it('WHEN validated THEN it returns an error mentioning trailing slash', () => {
      // ARRANGE
      const url = 'https://jira.example.com/';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toMatch(/trailing slash/);
    });
  });

  describe('GIVEN an invalid URL', () => {
    it('WHEN the input is not a URL THEN it returns an error', () => {
      // ARRANGE
      const url = 'not-a-url';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toBeDefined();
      expect(result).toMatch(/not a valid URL/);
    });

    it('WHEN the input is an empty string THEN it returns an error', () => {
      // ARRANGE
      const url = '';

      // ACT
      const result = checkJiraInstanceUrl(url);

      // ASSERT
      expect(result).toBeDefined();
    });
  });
});
