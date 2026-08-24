// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { BadRequestError } from '../../common/utils/httpErrors';
import { getIaCTemplateService, IaCFormatSchema } from '../services/iacTemplateService';
import { API_HEADERS } from './apiHandler';
import { BaseHandler, getClaims } from './baseHandler';
import { toDbFindingId } from '../../common/utils/findingUtils';

function decodePathParam(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    throw new BadRequestError('findingId contains malformed percent-encoding');
  }
}

const baseHandler = new BaseHandler(new Logger({ serviceName: SCOPE_NAME }));

/**
 * Handler for GET /iac/{findingId}
 *
 * Returns a rendered IaC template populated with real remediation data from
 * the finding. The body is JSON `{ content, filename, controlId }` and the
 * client (WebUI) is responsible for triggering the download — we don't set a
 * Content-Disposition header here because the response body needs to remain
 * JSON for error handling.
 */
async function getIaCTemplateContentHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  // Extract and URL-decode findingId from path parameters
  const rawFindingId = event.pathParameters?.findingId;
  if (!rawFindingId) {
    throw new BadRequestError('findingId path parameter is required');
  }
  const findingId = decodePathParam(rawFindingId);

  const sanitizedFindingId = toDbFindingId(findingId);
  if (!sanitizedFindingId) {
    throw new BadRequestError('findingId must be a Security Hub finding ARN');
  }

  // Validate format query parameter before touching DynamoDB.
  const formatResult = IaCFormatSchema.safeParse(event.queryStringParameters?.format);
  if (!formatResult.success) {
    throw new BadRequestError(`Invalid or missing format. Supported: ${IaCFormatSchema.options.join(', ')}`);
  }

  const iacTemplateService = getIaCTemplateService();

  // Authorize from the fetched entry's stored accountId. When no history entry
  // exists the account scope is unknown, so fail closed to Admin/DelegatedAdmin
  // rather than proceeding with permissive empty scope.
  const historyEntry = await iacTemplateService.fetchFindingForDownload(sanitizedFindingId);
  if (historyEntry) {
    await baseHandler.validateAccess(
      claims,
      baseHandler.createAccessRules(baseHandler.extractAccountIdsFromFindings([historyEntry])),
    );
  } else {
    await baseHandler.validateAccess(claims, baseHandler.createAdminOnlyAccessRules());
  }

  // Render the template from the already-fetched entry
  const result = await iacTemplateService.renderTemplateForFinding(historyEntry, sanitizedFindingId, formatResult.data);

  return {
    statusCode: 200,
    headers: {
      ...API_HEADERS.IAC,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ content: result.content, filename: result.filename, controlId: result.controlId }),
  };
}

export const getIaCTemplateContent = getIaCTemplateContentHandler;
