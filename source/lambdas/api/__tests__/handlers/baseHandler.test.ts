// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { z } from 'zod';
import { BaseHandler } from '../../handlers/baseHandler';
import { BadRequestError } from '../../../common/utils/httpErrors';

describe('BaseHandler', () => {
  let baseHandler: BaseHandler;
  let mockLogger: Logger;

  beforeEach(() => {
    mockLogger = new Logger({ serviceName: 'test' });
    jest.spyOn(mockLogger, 'error').mockImplementation();
    jest.spyOn(mockLogger, 'info').mockImplementation();
    jest.spyOn(mockLogger, 'debug').mockImplementation();
    jest.spyOn(mockLogger, 'warn').mockImplementation();

    baseHandler = new BaseHandler(mockLogger);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('extractValidatedBody', () => {
    const TestSchema = z.object({
      name: z.string(),
      age: z.number(),
      email: z.string().email(),
    });

    it('should successfully extract and validate a valid body', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 30,
          email: 'john@example.com',
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      const result = baseHandler.extractValidatedBody(event, TestSchema);

      expect(result).toEqual({
        name: 'John Doe',
        age: 30,
        email: 'john@example.com',
      });
    });

    it('should throw BadRequestError for invalid data', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 'thirty', // Invalid: should be number
          email: 'invalid-email', // Invalid: not a valid email
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      expect(() => {
        baseHandler.extractValidatedBody(event, TestSchema);
      }).toThrow(BadRequestError);
    });

    it('should throw BadRequestError with custom error prefix', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 'thirty',
          email: 'invalid-email',
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      expect(() => {
        baseHandler.extractValidatedBody(event, TestSchema, 'Custom validation error');
      }).toThrow('Custom validation error');
    });

    it('should handle empty body', () => {
      const event = {
        body: null,
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      expect(() => {
        baseHandler.extractValidatedBody(event, TestSchema);
      }).toThrow(BadRequestError);
    });

    it('should return correct TypeScript type', () => {
      const event = {
        body: {
          name: 'John Doe',
          age: 30,
          email: 'john@example.com',
        },
        httpMethod: 'POST',
        path: '/test',
        headers: {},
        requestContext: {} as any,
      } as any;

      const result = baseHandler.extractValidatedBody(event, TestSchema);

      expect(typeof result.name).toBe('string');
      expect(typeof result.age).toBe('number');
      expect(typeof result.email).toBe('string');
    });
  });
});
