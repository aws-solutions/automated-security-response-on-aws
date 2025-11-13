// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Utility class for standardized error handling and formatting
 */
export class ErrorUtils {
  private static readonly MAX_ERROR_LENGTH = 1000;

  /**
   * Formats an error message with character limit
   * @param error - The error to format (can be Error, string, or unknown)
   * @returns A formatted error message string (max 1000 chars)
   */
  static formatErrorMessage(error: unknown): string {
    let message: string;

    if (error instanceof Error) {
      message = error.message;
    } else if (typeof error === 'string') {
      message = error;
    } else {
      message = String(error);
    }

    if (message.length > this.MAX_ERROR_LENGTH) {
      return message.substring(0, this.MAX_ERROR_LENGTH) + '...';
    }

    return message;
  }
}
