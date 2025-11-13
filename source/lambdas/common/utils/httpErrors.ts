// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export const UNAUTHORIZED_ERROR_MESSAGE = 'Unable to authorize, credentials may be incorrect or invalid.';
export const FORBIDDEN_ERROR_MESSAGE = 'You are not authorized to access this endpoint.';
export const NOT_FOUND_ERROR_MESSAGE = 'Resource not found';
export const BAD_REQUEST_ERROR_MESSAGE = 'Bad request';

export class HttpError extends Error {
  public readonly statusCode: number;

  constructor(statusCode: number, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.name = 'HttpError';
  }
}

export class UnauthorizedError extends HttpError {
  constructor(message = UNAUTHORIZED_ERROR_MESSAGE) {
    super(401, message);
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends HttpError {
  constructor(message = FORBIDDEN_ERROR_MESSAGE) {
    super(403, message);
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends HttpError {
  constructor(message = NOT_FOUND_ERROR_MESSAGE) {
    super(404, message);
    this.name = 'NotFoundError';
  }
}

export class BadRequestError extends HttpError {
  constructor(message = BAD_REQUEST_ERROR_MESSAGE) {
    super(400, message);
    this.name = 'BadRequestError';
  }
}
