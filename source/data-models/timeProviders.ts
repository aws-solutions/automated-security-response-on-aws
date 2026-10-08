// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export interface Clock {
  now(): Date;
}

class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}

export const getClock = (): Clock => new SystemClock();

export interface Sleeper {
  sleep(milliseconds: number): Promise<void>;
}

class SystemSleeper implements Sleeper {
  async sleep(milliseconds: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, milliseconds));
  }
}

export const getSleeper = (): Sleeper => new SystemSleeper();
