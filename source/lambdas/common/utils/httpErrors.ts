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

export const SERVICE_UNAVAILABLE_ERROR_MESSAGE =
  'The service is temporarily unable to complete this request, please retry.';

export class ServiceUnavailableError extends HttpError {
  constructor(message = SERVICE_UNAVAILABLE_ERROR_MESSAGE) {
    super(503, message);
    this.name = 'ServiceUnavailableError';
  }
}

export const CONFLICT_ERROR_MESSAGE =
  'Data was modified by another user - please refresh, review updated state, and try again.';

export class VersionConflictError extends HttpError {
  public readonly currentVersion?: number;

  constructor(
    message = 'Version conflict: the configuration was modified by another request',
    options?: { currentVersion?: number },
  ) {
    super(409, message);
    this.name = 'VersionConflictError';
    this.currentVersion = options?.currentVersion;
  }
}

export class ConflictError extends HttpError {
  public readonly code?: string;
  public readonly context?: Record<string, unknown>;

  constructor(message = CONFLICT_ERROR_MESSAGE, options?: { code?: string; context?: Record<string, unknown> }) {
    super(409, message);
    this.name = 'ConflictError';
    this.code = options?.code;
    this.context = options?.context;
  }
}

export class TooManyRequestsError extends HttpError {
  constructor(message = 'Too many requests') {
    super(429, message);
    this.name = 'TooManyRequestsError';
  }
}

export class NotImplementedError extends HttpError {
  constructor(message = 'This feature is not yet implemented') {
    super(501, message);
    this.name = 'NotImplementedError';
  }
}
