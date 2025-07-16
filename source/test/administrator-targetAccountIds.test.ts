// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

describe('TargetAccountIDs Parameter Validation', () => {
  const MAX_LENGTH = 4096;

  const isValidParameter = (input: string): boolean => {
    if (input.length > MAX_LENGTH) return false;
    const allowedPattern = /^(ALL|\d{12}(,\s*\d{12})*)$/;
    return allowedPattern.test(input);
  };

  test('should accept "ALL" as valid input', () => {
    expect(isValidParameter('ALL')).toBe(true);
  });

  test('should accept valid comma-separated account IDs', () => {
    const input = '123456789012,987654321098';
    expect(isValidParameter(input)).toBe(true);
  });

  test('should reject input exceeding maximum length', () => {
    // Generate a string that exceeds 4096 characters
    const longInput = Array(342).fill('123456789012').join(',');

    expect(longInput.length).toBeGreaterThan(MAX_LENGTH);
    expect(isValidParameter(longInput)).toBe(false);
  });

  test('should reject invalid formats', () => {
    const invalidInputs = [
      'all', // lowercase not allowed
      '12345678901', // too short
      '1234567890123', // too long
      '123456789012,', // trailing comma
      ',123456789012', // leading comma
      '12345678901a', // non-numeric
      'ALL,123456789012', // mixing ALL with account IDs
    ];

    invalidInputs.forEach((input) => {
      expect(isValidParameter(input)).toBe(false);
    });
  });
});
