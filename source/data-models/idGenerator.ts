// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Injectable wrapper over `crypto.randomUUID()`, per ADR 0004.
 *
 * Lives here rather than under `source/lambdas` so `@asr/mcp` can use it too: lambdas depends
 * on mcp, so the reverse import would be a cycle. `crypto.randomUUID()` is available both in
 * Node and, through Web Crypto, in the browser bundle this package is compiled into.
 */
export interface IdGenerator {
  randomUUID(): string;
}

class CryptoIdGenerator implements IdGenerator {
  randomUUID(): string {
    return crypto.randomUUID();
  }
}

export const getIdGenerator = (): IdGenerator => new CryptoIdGenerator();
