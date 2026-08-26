// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { APIGatewayProxyEvent } from 'aws-lambda';
import { BadRequestError, ForbiddenError } from '../../../common/utils/httpErrors';
import { IaCRenderResult } from '../../services/iacTemplateService';
import { createMockEvent, TEST_REQUEST_CONTEXT, buildFindingIdForType } from '../utils';

// Mock the template service factory so the handler test exercises only handler
// logic (validation, decoding, account extraction, response shaping) without
// S3/DDB. getIaCTemplateService is the service-layer factory the handler calls.
// The handler fetches the finding's history entry once (for authorization) and
// renders from that same entry, so both methods are stubbed here.
const fetchFindingForDownloadMock = jest.fn<Promise<{ accountId: string } | null>, [string]>();
const renderTemplateForFindingMock = jest.fn<Promise<IaCRenderResult>, [unknown, string, string]>();
jest.mock('../../services/iacTemplateService', () => {
  const actual = jest.requireActual('../../services/iacTemplateService');
  return {
    ...actual,
    getIaCTemplateService: jest.fn(() => ({
      fetchFindingForDownload: fetchFindingForDownloadMock,
      renderTemplateForFinding: renderTemplateForFindingMock,
    })),
  };
});

// Stub BaseHandler.validateAccess: resolves by default, can be overridden per-test
// to simulate authorization denial. createAccessRules keeps its real
// implementation so we can assert the account ids derived from the fetched
// finding are passed to the access check.
//
// Justification for mocking own code (per Unit Testing Guidelines): the real
// boundary behind validateAccess is Cognito (CognitoService.getUserEmail) plus
// the UserAccountMappingRepository (DynamoDB) — both already covered by
// authorization.test.ts and exercised end-to-end by the Hydra integration
// suite. This handler test deliberately scopes to the handler's own logic
// (path-param decoding, ARN sanitization, account extraction, format
// validation, response shaping); stubbing validateAccess keeps that scope
// focused and avoids re-testing the authorization stack through the handler.
import { BaseHandler } from '../../handlers/baseHandler';
const validateAccessSpy = jest
  .spyOn(BaseHandler.prototype, 'validateAccess')
  .mockResolvedValue({ username: 'tester', groups: ['AdminGroup'], email: 't@example.com' });
const createAccessRulesSpy = jest.spyOn(BaseHandler.prototype, 'createAccessRules');
const createAdminOnlyAccessRulesSpy = jest.spyOn(BaseHandler.prototype, 'createAdminOnlyAccessRules');

// Import after mocks are registered.
import { getIaCTemplateContent } from '../../handlers/iacTemplateContent';

const VALID_FINDING_ID = buildFindingIdForType('security-control/S3.2');

function eventFor(
  findingId: string | undefined,
  queryStringParameters: Record<string, string> | null = { format: 'cloudformation-yaml' },
): APIGatewayProxyEvent {
  return createMockEvent({
    httpMethod: 'GET',
    path: '/iac/findingId',
    pathParameters: findingId === undefined ? null : { findingId },
    queryStringParameters,
    requestContext: {
      ...TEST_REQUEST_CONTEXT,
      authorizer: { claims: { username: 'tester', 'cognito:groups': 'AdminGroup' } },
    },
  });
}

describe('getIaCTemplateContent handler', () => {
  beforeEach(() => {
    fetchFindingForDownloadMock.mockReset();
    fetchFindingForDownloadMock.mockResolvedValue({ accountId: '111122223333' });
    renderTemplateForFindingMock.mockReset();
    validateAccessSpy.mockClear();
    createAccessRulesSpy.mockClear();
    createAdminOnlyAccessRulesSpy.mockClear();
    validateAccessSpy.mockResolvedValue({ username: 'tester', groups: ['AdminGroup'], email: 't@example.com' });
  });

  describe('successful render', () => {
    it('returns 200 with content, filename, and controlId and IAC CORS headers', async () => {
      renderTemplateForFindingMock.mockResolvedValue({
        content: 'Bucket: my-bucket',
        filename: 'S3.2.yaml.txt',
        controlId: 'S3.2',
      });

      const result = await getIaCTemplateContent(eventFor(VALID_FINDING_ID));

      expect(result.statusCode).toBe(200);
      expect(result.headers).toEqual(
        expect.objectContaining({
          'Content-Type': 'application/json',
          'Access-Control-Allow-Methods': 'GET,OPTIONS',
        }),
      );
      expect(JSON.parse(result.body)).toEqual({
        content: 'Bucket: my-bucket',
        filename: 'S3.2.yaml.txt',
        controlId: 'S3.2',
      });
      // The already-fetched history entry and sanitized findingId are passed to the render.
      expect(renderTemplateForFindingMock).toHaveBeenCalledWith(
        { accountId: '111122223333' },
        expect.any(String),
        'cloudformation-yaml',
      );
    });

    it('URL-decodes a percent-encoded findingId before processing', async () => {
      renderTemplateForFindingMock.mockResolvedValue({ content: 'x', filename: 'S3.2.yaml.txt', controlId: 'S3.2' });

      const encoded = encodeURIComponent(VALID_FINDING_ID);
      const result = await getIaCTemplateContent(eventFor(encoded));

      expect(result.statusCode).toBe(200);
      expect(fetchFindingForDownloadMock).toHaveBeenCalledTimes(1);
      expect(renderTemplateForFindingMock).toHaveBeenCalledTimes(1);
    });
  });

  describe('findingId validation', () => {
    it('throws BadRequestError when findingId path parameter is missing', async () => {
      await expect(getIaCTemplateContent(eventFor(undefined))).rejects.toThrow(BadRequestError);
      expect(fetchFindingForDownloadMock).not.toHaveBeenCalled();
      expect(renderTemplateForFindingMock).not.toHaveBeenCalled();
    });

    it('throws BadRequestError when findingId has malformed percent-encoding', async () => {
      await expect(getIaCTemplateContent(eventFor('%E0%A4%A'))).rejects.toThrow(
        'findingId contains malformed percent-encoding',
      );
    });

    it('throws BadRequestError when findingId is not a Security Hub ARN', async () => {
      await expect(getIaCTemplateContent(eventFor('not-an-arn'))).rejects.toThrow(
        'findingId must be a Security Hub finding ARN',
      );
    });
  });

  describe('format validation', () => {
    it('throws BadRequestError when format is missing', async () => {
      await expect(getIaCTemplateContent(eventFor(VALID_FINDING_ID, null))).rejects.toThrow(BadRequestError);
    });

    it('throws BadRequestError when format is unsupported', async () => {
      await expect(getIaCTemplateContent(eventFor(VALID_FINDING_ID, { format: 'ansible' }))).rejects.toThrow(
        /Invalid or missing format/,
      );
      expect(fetchFindingForDownloadMock).not.toHaveBeenCalled();
      expect(renderTemplateForFindingMock).not.toHaveBeenCalled();
    });
  });

  describe('authorization', () => {
    it('propagates ForbiddenError from validateAccess', async () => {
      validateAccessSpy.mockRejectedValue(new ForbiddenError('Insufficient permissions'));

      await expect(getIaCTemplateContent(eventFor(VALID_FINDING_ID))).rejects.toThrow(ForbiddenError);
      expect(renderTemplateForFindingMock).not.toHaveBeenCalled();
    });

    it('authorizes against the account id from the fetched finding record', async () => {
      renderTemplateForFindingMock.mockResolvedValue({ content: 'x', filename: 'S3.2.yaml.txt', controlId: 'S3.2' });

      await getIaCTemplateContent(eventFor(VALID_FINDING_ID));

      expect(createAccessRulesSpy).toHaveBeenCalledWith(['111122223333']);
      expect(createAdminOnlyAccessRulesSpy).not.toHaveBeenCalled();
      expect(validateAccessSpy).toHaveBeenCalledWith(
        expect.objectContaining({ username: 'tester' }),
        expect.objectContaining({ requiredGroups: expect.arrayContaining(['AdminGroup']) }),
      );
    });

    it('fails closed to an admin-only check (no account scope) when no history entry exists', async () => {
      fetchFindingForDownloadMock.mockResolvedValue(null);
      renderTemplateForFindingMock.mockResolvedValue({
        content: '# unavailable',
        filename: 'S3.2-iac-unavailable.txt',
        controlId: 'S3.2',
      });

      const result = await getIaCTemplateContent(eventFor(VALID_FINDING_ID));

      // Account scope can't be determined, so the admin-only rule is used and
      // the permissive empty-scope createAccessRules path is not taken.
      expect(createAdminOnlyAccessRulesSpy).toHaveBeenCalledTimes(1);
      expect(createAccessRulesSpy).not.toHaveBeenCalled();
      expect(result.statusCode).toBe(200);
      expect(renderTemplateForFindingMock).toHaveBeenCalledWith(null, expect.any(String), 'cloudformation-yaml');
    });
  });
});
