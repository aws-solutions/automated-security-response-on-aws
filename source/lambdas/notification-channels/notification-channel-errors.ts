// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export class SecretRetrievalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretRetrievalError';
  }
}

export class CredentialParsingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialParsingError';
  }
}

export class InputValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputValidationError';
  }
}

export class ChannelApiError extends Error {
  public readonly statusCode: number;

  constructor(channelName: string, statusCode: number, body: string) {
    super(`${channelName} API returned ${statusCode}: ${body}`);
    this.name = 'ChannelApiError';
    this.statusCode = statusCode;
  }
}

/** A channel request failed in transit: it timed out or the response was too large. */
export class ChannelTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChannelTransportError';
  }
}
