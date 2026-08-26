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
import { FiltersService } from '../services/filtersService';
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

async function deleteFilterHandler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const claims = getClaims(event);

  const user = await baseHandler.validateAccess(claims, {
    requiredGroups: ['AdminGroup', 'DelegatedAdminGroup'],
  });

  const filterId = baseHandler.extractValidatedPathId(event, 'filterId');

  const result = await filtersService.deleteFilter(filterId, user.email);

  if (result.failedControlIds.length > 0) {
    return createResponse(
      207,
      {
        message: 'Some controls failed to update. Filter was not deleted. Please retry.',
        failedControlIds: result.failedControlIds,
      },
      API_HEADERS.FILTERS,
    );
  }

  return createResponse(
    200,
    {
      message: 'Filter deleted successfully',
      affectedControlIds: result.affectedControlIds,
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
