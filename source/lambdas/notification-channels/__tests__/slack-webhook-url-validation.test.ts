// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { validateSlackWebhookUrl, SlackWebhookUrl } from '../slack-channel';
import { CredentialParsingError } from '../notification-channel-errors';

describe('validateSlackWebhookUrl', () => {
  describe('GIVEN a valid Slack webhook URL', () => {
    it('WHEN the URL matches the expected pattern THEN it returns the URL as a branded SlackWebhookUrl', () => {
      // ARRANGE
      const validUrl = 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123';

      // ACT
      const result: SlackWebhookUrl = validateSlackWebhookUrl(validUrl);

      // ASSERT
      expect(result).toBe(validUrl);
    });

    it('WHEN the URL has longer segment values THEN it returns the URL as a branded SlackWebhookUrl', () => {
      // ARRANGE
      const validUrl = 'https://hooks.slack.com/services/TABCDEFGH12/BABCDEFGH12/abcdefghijklmnopqrstuvwxyz0123456789';

      // ACT
      const result: SlackWebhookUrl = validateSlackWebhookUrl(validUrl);

      // ASSERT
      expect(result).toBe(validUrl);
    });

    it('WHEN the workspace and bot segments contain mixed-case characters THEN it returns the URL as a branded SlackWebhookUrl', () => {
      // ARRANGE
      const validUrl = 'https://hooks.slack.com/services/TabcDEF123/BabcDEF456/tokenValue789';

      // ACT
      const result: SlackWebhookUrl = validateSlackWebhookUrl(validUrl);

      // ASSERT
      expect(result).toBe(validUrl);
    });
  });

  describe('GIVEN a URL exceeding 2,048 characters', () => {
    it('WHEN validated THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const longUrl = 'https://hooks.slack.com/services/TABC/' + 'A'.repeat(2048);

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(longUrl)).toThrow(CredentialParsingError);
      expect(() => validateSlackWebhookUrl(longUrl)).toThrow(/exceeds maximum length/);
    });
  });

  describe('GIVEN a URL with query parameters', () => {
    it('WHEN validated THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const urlWithQuery = 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123?foo=bar';

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(urlWithQuery)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a URL with fragments', () => {
    it('WHEN validated THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const urlWithFragment = 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123#section';

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(urlWithFragment)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a URL with a trailing slash', () => {
    it('WHEN validated THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const urlWithTrailingSlash = 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123/';

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(urlWithTrailingSlash)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a non-HTTPS URL', () => {
    it('WHEN validated THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const httpUrl = 'http://hooks.slack.com/services/T0123ABC/B0123DEF/abcXYZ123';

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(httpUrl)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a URL with the wrong domain', () => {
    it('WHEN validated THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const wrongDomainUrl = 'https://evil.com/services/T0123ABC/B0123DEF/abcXYZ123';

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(wrongDomainUrl)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a URL missing workspace/bot/token segments', () => {
    it.each([
      ['missing workspace', 'https://hooks.slack.com/services/B0123DEF/abcXYZ123'],
      ['missing bot', 'https://hooks.slack.com/services/T0123ABC/abcXYZ123'],
      ['missing token', 'https://hooks.slack.com/services/T0123ABC/B0123DEF'],
      ['base path only', 'https://hooks.slack.com/services/'],
    ])('WHEN %s THEN it throws CredentialParsingError', (_label, url) => {
      expect(() => validateSlackWebhookUrl(url)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN an invalid URL', () => {
    it('WHEN validated THEN the error message does not contain the URL', () => {
      // ARRANGE
      const invalidUrl = 'https://evil.com/services/T0123ABC/B0123DEF/secretToken123';

      // ACT
      let errorMessage = '';
      try {
        validateSlackWebhookUrl(invalidUrl);
      } catch (error) {
        errorMessage = (error as Error).message;
      }

      // ASSERT
      expect(errorMessage).not.toContain(invalidUrl);
      expect(errorMessage).not.toContain('secretToken123');
    });

    it('WHEN validated THEN the error message is descriptive', () => {
      // ARRANGE
      const invalidUrl = 'https://evil.com/services/T0123ABC/B0123DEF/abcXYZ123';

      // ACT & ASSERT
      expect(() => validateSlackWebhookUrl(invalidUrl)).toThrow(/webhook URL/i);
    });
  });
});
