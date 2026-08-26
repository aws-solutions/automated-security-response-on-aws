// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export interface IdGenerator {
  randomUUID(): string;
}

class CryptoIdGenerator implements IdGenerator {
  randomUUID(): string {
    return crypto.randomUUID();
  }
}

export const getIdGenerator = (): IdGenerator => new CryptoIdGenerator();
