// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ItemCollectionSizeLimitExceededException } from '@aws-sdk/client-dynamodb';
import { isItemCollectionSizeLimitError } from '../dynamodb';

describe('isItemCollectionSizeLimitError', () => {
  const namedError = (name: string, message: string): Error => Object.assign(new Error(message), { name });

  it('recognises the modeled SDK exception regardless of message', () => {
    const error = new ItemCollectionSizeLimitExceededException({
      message: 'Item collection size limit exceeded',
      $metadata: { httpStatusCode: 400 },
    });

    expect(isItemCollectionSizeLimitError(error)).toBe(true);
  });

  it('recognises the ValidationException wire form seen in production', () => {
    expect(isItemCollectionSizeLimitError(namedError('ValidationException', 'Collection size exceeded'))).toBe(true);
  });

  it('matches the message case-insensitively and with trailing punctuation', () => {
    expect(isItemCollectionSizeLimitError(namedError('ValidationException', 'collection SIZE exceeded.'))).toBe(true);
  });

  it('recognises an un-modeled error carrying the SDK exception name and message', () => {
    expect(
      isItemCollectionSizeLimitError(
        namedError('ItemCollectionSizeLimitExceededException', 'Collection size exceeded'),
      ),
    ).toBe(true);
  });

  it('rejects a ValidationException with an unrelated message', () => {
    expect(
      isItemCollectionSizeLimitError(
        namedError('ValidationException', 'Item size has exceeded the maximum allowed size'),
      ),
    ).toBe(false);
  });

  it('rejects the collection-size message when raised by a different error type', () => {
    expect(
      isItemCollectionSizeLimitError(namedError('ProvisionedThroughputExceededException', 'Collection size exceeded')),
    ).toBe(false);
  });

  it('rejects values that are not Error instances', () => {
    expect(isItemCollectionSizeLimitError('Collection size exceeded')).toBe(false);
    expect(isItemCollectionSizeLimitError({ name: 'ValidationException', message: 'Collection size exceeded' })).toBe(
      false,
    );
    expect(isItemCollectionSizeLimitError(undefined)).toBe(false);
  });
});
