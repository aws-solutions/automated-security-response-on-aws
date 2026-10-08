// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export class MissingParameterError extends Error {
  constructor(toolName: string, parameterName: string, hint?: string) {
    super(`${toolName}: ${parameterName} is required.${hint ? ` ${hint}` : ''}`);
    this.name = 'MissingParameterError';
  }
}

/** A tool argument was well-formed but rejected on validation grounds (e.g. a disallowed value). */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/** A caller-supplied path escaped (or would escape) the boundary it was checked against. */
export class PathContainmentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PathContainmentError';
  }
}

/**
 * The caller is not authorized for the account that owns the data they asked for.
 *
 * Distinct from `ValidationError`: the request was well-formed and the resource may
 * well exist — the caller simply may not see it. Kept separate so the handler can map
 * it to 403 rather than 400.
 */
export class AccountAuthorizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AccountAuthorizationError';
  }
}
