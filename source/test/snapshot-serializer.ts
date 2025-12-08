// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Jest snapshot serializer to normalize Lambda S3 keys
 * Removes content hashes from Lambda zip filenames to prevent snapshot changes
 * when Lambda code changes but infrastructure doesn't
 */
// Use CommonJS module syntax for compatibility with Jest
module.exports = {
  test(val: unknown): boolean {
    return typeof val === 'string' && /\/lambda\/.*\.zip$/.test(val);
  },
  serialize(val: string): string {
    // Replace 8-character hash with original filename
    return val.replace(/-[a-f0-9]{8}\.zip$/, '.zip');
  },
};
