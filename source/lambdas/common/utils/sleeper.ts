// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export interface Sleeper {
  sleep(ms: number): Promise<void>;
}

class SystemSleeper implements Sleeper {
  async sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export const getSleeper = (): Sleeper => new SystemSleeper();
