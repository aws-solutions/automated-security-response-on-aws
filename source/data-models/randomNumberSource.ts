// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/** Injectable source of random numbers, per ADR 0004. */
export interface RandomNumberSource {
  /** Returns a value from 0 up to, but not including, 1. */
  next(): number;
}

const UINT32_RANGE = 2 ** 32;

class CryptoRandomNumberSource implements RandomNumberSource {
  next(): number {
    return crypto.getRandomValues(new Uint32Array(1))[0] / UINT32_RANGE;
  }
}

export const getRandomNumberSource = (): RandomNumberSource => new CryptoRandomNumberSource();
