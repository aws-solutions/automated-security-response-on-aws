// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  MissingEnvironmentVariableError,
  readOptionalEnvironmentVariables,
  requireEnvironmentVariables,
} from '../utils/env-variables';

describe('environment variable helpers', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.ENV_VARIABLES_TEST_A;
    delete process.env.ENV_VARIABLES_TEST_B;
    delete process.env.ENV_VARIABLES_TEST_C;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('requireEnvironmentVariables', () => {
    it('returns the value of every requested variable', () => {
      process.env.ENV_VARIABLES_TEST_A = 'alpha';
      process.env.ENV_VARIABLES_TEST_B = 'beta';

      const result = requireEnvironmentVariables(['ENV_VARIABLES_TEST_A', 'ENV_VARIABLES_TEST_B']);

      expect(result).toEqual({ ENV_VARIABLES_TEST_A: 'alpha', ENV_VARIABLES_TEST_B: 'beta' });
    });

    it('returns an empty record when no variables are requested', () => {
      expect(requireEnvironmentVariables([])).toEqual({});
    });

    it('lists every missing variable in one error', () => {
      process.env.ENV_VARIABLES_TEST_A = 'alpha';

      const act = () =>
        requireEnvironmentVariables(['ENV_VARIABLES_TEST_A', 'ENV_VARIABLES_TEST_B', 'ENV_VARIABLES_TEST_C']);

      expect(act).toThrow(MissingEnvironmentVariableError);
      expect(act).toThrow('Missing required environment variables: ENV_VARIABLES_TEST_B, ENV_VARIABLES_TEST_C');
    });

    it('treats an empty value as missing', () => {
      process.env.ENV_VARIABLES_TEST_A = '';

      expect(() => requireEnvironmentVariables(['ENV_VARIABLES_TEST_A'])).toThrow(MissingEnvironmentVariableError);
    });

    it('exposes the missing names and a stable error name', () => {
      let caught: unknown;
      try {
        requireEnvironmentVariables(['ENV_VARIABLES_TEST_B']);
      } catch (error) {
        caught = error;
      }

      expect(caught).toBeInstanceOf(MissingEnvironmentVariableError);
      expect((caught as MissingEnvironmentVariableError).name).toBe('MissingEnvironmentVariableError');
      expect((caught as MissingEnvironmentVariableError).missingVariables).toEqual(['ENV_VARIABLES_TEST_B']);
    });
  });

  describe('readOptionalEnvironmentVariables', () => {
    it('returns only the variables that are set and not empty', () => {
      process.env.ENV_VARIABLES_TEST_A = 'alpha';
      process.env.ENV_VARIABLES_TEST_B = '';

      const result = readOptionalEnvironmentVariables([
        'ENV_VARIABLES_TEST_A',
        'ENV_VARIABLES_TEST_B',
        'ENV_VARIABLES_TEST_C',
      ]);

      expect(result).toEqual({ ENV_VARIABLES_TEST_A: 'alpha' });
    });

    it('never throws when nothing is set', () => {
      expect(readOptionalEnvironmentVariables(['ENV_VARIABLES_TEST_A'])).toEqual({});
    });
  });
});
