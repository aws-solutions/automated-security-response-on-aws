// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { validateSlackChannelId } from '../slack-channel';
import { CredentialParsingError } from '../notification-channel-errors';

describe('validateSlackChannelId', () => {
  describe('GIVEN a valid Slack channel ID', () => {
    it('WHEN the ID matches the expected pattern THEN it does not throw', () => {
      // ARRANGE
      const validChannelId = 'C0123456789';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(validChannelId)).not.toThrow();
    });

    it('WHEN the ID contains uppercase letters and digits THEN it does not throw', () => {
      // ARRANGE
      const validChannelId = 'CABCDEF0123';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(validChannelId)).not.toThrow();
    });
  });

  describe('GIVEN a channel ID not starting with C', () => {
    it('WHEN the ID starts with a different letter THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const invalidChannelId = 'D0123456789';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(invalidChannelId)).toThrow(CredentialParsingError);
    });

    it('WHEN the ID starts with a digit THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const invalidChannelId = '00123456789';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(invalidChannelId)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a valid Slack channel ID of varying length', () => {
    it.each([
      ['9 characters (legacy)', 'C0123ABCD'],
      ['11 characters (standard)', 'C0123456789'],
      ['13 characters (newer)', 'C0123ABCDEFGH'],
    ])('WHEN the ID is %s THEN it does not throw', (_label, channelId) => {
      expect(() => validateSlackChannelId(channelId)).not.toThrow();
    });
  });

  describe('GIVEN an empty channel ID', () => {
    it('WHEN the ID is empty THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const empty = '';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(empty)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a channel ID with lowercase characters', () => {
    it('WHEN the ID contains lowercase letters THEN it throws CredentialParsingError', () => {
      // ARRANGE
      const lowercaseId = 'Cabcdef0123';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(lowercaseId)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN a channel ID with special characters', () => {
    it.each([
      ['hyphens', 'C0123-56789'],
      ['underscores', 'C0123_56789'],
      ['hash prefix', '#general'],
    ])('WHEN the ID contains %s THEN it throws CredentialParsingError', (_label, channelId) => {
      expect(() => validateSlackChannelId(channelId)).toThrow(CredentialParsingError);
    });
  });

  describe('GIVEN an invalid channel ID', () => {
    it('WHEN validated THEN the error message is descriptive', () => {
      // ARRANGE
      const invalidId = 'invalid-id';

      // ACT & ASSERT
      expect(() => validateSlackChannelId(invalidId)).toThrow(/channel ID/i);
    });

    it('WHEN validated THEN the error includes the invalid value', () => {
      // ARRANGE
      const invalidId = 'XINVALID123';

      // ACT
      let errorMessage = '';
      try {
        validateSlackChannelId(invalidId);
      } catch (error) {
        errorMessage = (error as Error).message;
      }

      // ASSERT
      expect(errorMessage).toContain('XINVALID123');
    });
  });
});
