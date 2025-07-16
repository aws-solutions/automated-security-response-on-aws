// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import TicketingFunctionNameParam from '../ticketing-function-name-param';

describe('functionNameRegex', () => {
  const regex = new RegExp(TicketingFunctionNameParam.functionNameRegex);

  test('should match empty string', () => {
    expect(regex.test('')).toBe(true);
  });

  test('should match valid function names', () => {
    expect(regex.test('validFunction')).toBe(true);
    expect(regex.test('valid-function')).toBe(true);
    expect(regex.test('valid_function')).toBe(true);
    expect(regex.test('valid123')).toBe(true);
    expect(regex.test('a'.repeat(64))).toBe(true);
  });

  test('should not match names longer than 64 characters', () => {
    expect(regex.test('a'.repeat(65))).toBe(false);
  });

  test('should not match names with invalid characters', () => {
    expect(regex.test('invalid!')).toBe(false);
    expect(regex.test('invalid@function')).toBe(false);
    expect(regex.test('invalid space')).toBe(false);
  });
});
