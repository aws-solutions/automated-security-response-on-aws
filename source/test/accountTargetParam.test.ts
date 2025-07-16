// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import AccountTargetParam from '../lib/parameters/account-target-param';
import { EventPatternHelper } from '../lib/cdk-helper/eventeattern-helper';

describe('AccountTargetParam', () => {
  let stack: Stack;

  beforeEach(() => {
    stack = new Stack();
  });

  it('creates parameters with correct defaults', () => {
    new AccountTargetParam(stack, 'TestParams');

    const template = Template.fromStack(stack);
    template.hasParameter('TargetAccountIDs', {
      Type: 'String',
      Default: 'ALL',
      AllowedPattern: '^(ALL|\\d{12}(,\\s*\\d{12})*)$',
      MaxLength: EventPatternHelper.getPatternMaxLength(),
    });

    template.hasParameter('TargetAccountIDsStrategy', {
      Type: 'String',
      Default: 'INCLUDE',
      AllowedValues: ['INCLUDE', 'EXCLUDE'],
    });
  });

  it('validates account ID pattern', () => {
    const regex = new RegExp(AccountTargetParam.targetAccountIDsParameterRegex);
    expect(regex.test('123456789012')).toBeTruthy();
    expect(regex.test('123456789012,987654321098')).toBeTruthy();
    expect(regex.test('ALL')).toBeTruthy();
  });

  it('enforces maximum length constraint', () => {
    // WHEN
    const construct = new AccountTargetParam(stack, 'TestParams');

    // THEN
    expect(construct.targetAccountIDs.maxLength).toBeLessThanOrEqual(4096);
    expect(construct.targetAccountIDs.maxLength).toBe(EventPatternHelper.getPatternMaxLength());
  });

  it('has correct strategy values', () => {
    // WHEN
    const construct = new AccountTargetParam(stack, 'TestParams');

    // THEN
    expect(construct.targetAccountIDsStrategy.allowedValues).toEqual(['INCLUDE', 'EXCLUDE']);
    expect(construct.targetAccountIDsStrategy.default).toBe('INCLUDE');
  });

  describe('Parameter Validation', () => {
    it('accepts valid account ID lists', () => {
      const validPatterns = [
        'ALL',
        '123456789012',
        '123456789012,987654321098',
        '123456789012, 987654321098', // with space
      ];

      const regex = new RegExp('^(ALL|\\d{12}(,\\s*\\d{12})*)$');
      validPatterns.forEach((pattern) => {
        expect(regex.test(pattern)).toBeTruthy();
      });
    });

    it('rejects invalid account ID lists', () => {
      const invalidPatterns = [
        '',
        'NONE',
        '12345', // too short
        '123456789012,123', // second ID too short
        'ABC456789012', // contains letters
        '123456789012,', // trailing comma
        ',123456789012', // leading comma
      ];

      const regex = new RegExp('^(ALL|\\d{12}(,\\s*\\d{12})*)$');
      invalidPatterns.forEach((pattern) => {
        expect(regex.test(pattern)).toBeFalsy();
      });
    });
  });
});

// Optional: Additional tests for edge cases and integration

describe('AccountTargetParam Integration', () => {
  it('works with EventPatternHelper maximum length', () => {
    const stack = new Stack();
    const construct = new AccountTargetParam(stack, 'TestParams');

    expect(construct.targetAccountIDs.maxLength).toBe(EventPatternHelper.getPatternMaxLength());
  });

  it('handles maximum number of accounts', () => {
    const maxLength = EventPatternHelper.getPatternMaxLength();
    const accountsPerLine = Math.floor(maxLength / 13);
    const accounts = Array(accountsPerLine).fill('123456789012').join(',');

    const regex = new RegExp('^(ALL|\\d{12}(,\\s*\\d{12})*)$');
    expect(regex.test(accounts)).toBeTruthy();
    expect(accounts.length).toBeLessThanOrEqual(maxLength);
  });
});
