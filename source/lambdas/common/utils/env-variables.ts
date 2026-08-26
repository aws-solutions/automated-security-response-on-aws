// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Thrown when one or more required environment variables are missing at Lambda
 * startup. The error message lists all missing variable names so operators can
 * fix the deployment in a single pass.
 */
export class MissingEnvironmentVariableError extends Error {
  public readonly missingVariables: string[];

  constructor(missingVariables: string[]) {
    super(`Missing required environment variables: ${missingVariables.join(', ')}`);
    this.name = 'MissingEnvironmentVariableError';
    this.missingVariables = missingVariables;
  }
}

/**
 * Reads the given keys from `process.env`, validates that every one is present,
 * and returns a typed record where all values are guaranteed to be `string`.
 * Throws {@link MissingEnvironmentVariableError} listing every missing key.
 *
 * The return type is `Record<K, string>`, so the caller gets compile-time key
 * safety without needing non-null assertions.
 */
export function requireEnvironmentVariables<K extends string>(keys: readonly K[]): Record<K, string> {
  const missing = keys.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new MissingEnvironmentVariableError(missing);
  }

  const result = {} as Record<K, string>;
  for (const key of keys) {
    // type cast is justified, Lambda env variables are strings after the null check above
    result[key] = process.env[key] as string;
  }
  return result;
}

/**
 * Reads the given optional keys from `process.env`, omitting any that are absent or empty. Unlike
 * {@link requireEnvironmentVariables} this never throws, so it suits environment variables that are
 * part of a Lambda's typed contract but not guaranteed present in every deployment. Callers must
 * handle the resulting `undefined`.
 */
export function readOptionalEnvironmentVariables<K extends string>(keys: readonly K[]): Partial<Record<K, string>> {
  const result: Partial<Record<K, string>> = {};
  for (const key of keys) {
    const value = process.env[key];
    if (value) {
      result[key] = value;
    }
  }
  return result;
}
