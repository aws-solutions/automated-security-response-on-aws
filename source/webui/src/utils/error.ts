// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { FetchBaseQueryError } from '@reduxjs/toolkit/query';

/**
 * Type predicate to narrow an unknown error to `FetchBaseQueryError`
 */
export function isFetchBaseQueryError(error: unknown): error is FetchBaseQueryError {
  return typeof error === 'object' && error != null && 'status' in error;
}

/**
 * Type predicate to narrow an unknown error to an object with a string 'message' property
 */
export function isErrorWithMessage(error: unknown): error is { message: string } {
  return typeof error === 'object' && error != null && 'message' in error && typeof (error as any).message === 'string';
}

export function getErrorMessage(error: unknown): string | undefined {
  if (isErrorWithMessage(error)) {
    return error.message;
  } else if (isFetchBaseQueryError(error)) {
    return 'error' in error ? error.error : JSON.stringify(error.data);
  }
}
