// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';
import {
  CreateFilterRequest,
  CreateFilterRequestSchema,
  UpdateFilterRequest,
  UpdateFilterRequestSchema,
} from '@asr/data-models';
import { SCOPE_NAME } from '../../common/constants/apiConstant';
import { sendMetrics } from '../../common/utils/metricsUtils';
import { ControlsService } from '../services/controlsService';
import { FiltersService, type DeleteFilterResult } from '../services/filtersService';
import { API_HEADERS, createResponse } from './apiHandler';
import { BaseHandler, getClaims } from './baseHandler';

const logger = new Logger({ serviceName: SCOPE_NAME });
const tracer = new Tracer({ serviceName: SCOPE_NAME });
const baseHandler = new BaseHandler(logger);
const controlsService = new ControlsService(logger);
const filtersService = new FiltersService(logger, controlsService);

async function getFiltersHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup', 'AccountOperatorGroup'],
  });

  const result = await filtersService.getAllFilters();

  return createResponse(200, result, API_HEADERS.FILTERS);
}

async function updateFilterHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
  });

  const filterId = baseHandler.extractValidatedPathId(event, 'filterId');

  const body = baseHandler.extractValidatedBody<UpdateFilterRequest>(
    event,
    UpdateFilterRequestSchema,
    'Invalid filter update request',
  );

  const updatedFilter = await filtersService.updateFilter(filterId, body, user.email);

  return createResponse(200, updatedFilter, API_HEADERS.FILTERS);
}

async function createFilterHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
  });

  const body = baseHandler.extractValidatedBody<CreateFilterRequest>(
    event,
    CreateFilterRequestSchema,
    'Invalid filter creation request',
  );

  const createdFilter = await filtersService.createFilter(body, user.email);

  await sendMetrics({ filter_created: { filter_name: body.name } });

  return createResponse(201, createdFilter, API_HEADERS.FILTERS);
}

/** The 200 body's message for a filter delete that did not partially fail. */
function deleteFilterMessage(result: DeleteFilterResult): string {
  if (result.deleted) return 'Filter deleted successfully';
  if (result.alreadyAbsent) return 'Filter already absent';
  return 'Filter row was already absent; removed its dangling references from the listed controls';
}

async function deleteFilterHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
  });

  const filterId = baseHandler.extractValidatedPathId(event, 'filterId');

  const result = await filtersService.deleteFilter(filterId, user.email);

  if (result.stillAttachedControlIds.length > 0) {
    // Partial detach. The filter is kept so no control references a filter that does not
    // exist, but the detached controls have already been widened — the body has to say both,
    // and the WebUI must not read this as a completed deletion (it is a 207, not a 2xx success).
    return createResponse(
      207,
      {
        message:
          'Filter was NOT deleted: some controls still reference it. Controls listed in ' +
          'detachedControlIds no longer apply this filter; retry to detach the rest and delete it.',
        deleted: false,
        detachedControlIds: result.detachedControlIds,
        stillAttachedControlIds: result.stillAttachedControlIds,
      },
      API_HEADERS.FILTERS,
    );
  }

  // Stays 200 when the filter was already gone: DELETE is idempotent, and the WebUI treats any
  // non-2xx as a failure toast. Only the message and the `deleted` flag differ, so a cleanup
  // script or an agent reading the body can tell a real teardown from a typo'd id — the same
  // shape the notification DELETE returns. `affectedControlIds` is kept as the older name for
  // `detachedControlIds`.
  return createResponse(
    200,
    {
      message: deleteFilterMessage(result),
      deleted: result.deleted,
      detachedControlIds: result.detachedControlIds,
      affectedControlIds: result.detachedControlIds,
    },
    API_HEADERS.FILTERS,
  );
}

export const getFilters = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');

  const middlewareHandler = middy(getFiltersHandler).use(injectLambdaContext(logger)).use(captureLambdaHandler(tracer));

  return middlewareHandler(event, context);
};

export const updateFilter = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(updateFilterHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer))
    .use(httpJsonBodyParser());

  return middlewareHandler(event, context);
};

export const createFilter = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  const { default: httpJsonBodyParser } = (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');

  const middlewareHandler = middy(createFilterHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer))
    .use(httpJsonBodyParser());

  return middlewareHandler(event, context);
};

export const deleteFilter = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const { default: middy } = (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');

  const middlewareHandler = middy(deleteFilterHandler)
    .use(injectLambdaContext(logger))
    .use(captureLambdaHandler(tracer));

  return middlewareHandler(event, context);
};
