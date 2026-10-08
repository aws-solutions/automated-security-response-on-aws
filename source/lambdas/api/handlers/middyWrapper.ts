// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { injectLambdaContext } from '@aws-lambda-powertools/logger/middleware';
import { Tracer } from '@aws-lambda-powertools/tracer';
import { captureLambdaHandler } from '@aws-lambda-powertools/tracer/middleware';
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { dynamicImport } from 'tsimportlib';

export type RouteHandler = (event: APIGatewayProxyEvent, context: Context) => Promise<APIGatewayProxyResult>;

// The ESM interop resolution is the same for every invocation, so it is done once
// per container and reused on warm invocations instead of on each request. A
// failed import leaves the slot unset so the next request retries rather than
// caching the failure for the life of the container.
let middyCore: typeof import('@middy/core') | undefined;
let httpJsonBodyParserModule: typeof import('@middy/http-json-body-parser') | undefined;

async function loadMiddyCore(): Promise<typeof import('@middy/core')> {
  middyCore ??= (await dynamicImport('@middy/core', module)) as typeof import('@middy/core');
  return middyCore;
}

async function loadHttpJsonBodyParser(): Promise<typeof import('@middy/http-json-body-parser')> {
  httpJsonBodyParserModule ??= (await dynamicImport(
    '@middy/http-json-body-parser',
    module,
  )) as typeof import('@middy/http-json-body-parser');
  return httpJsonBodyParserModule;
}

/**
 * Wraps an internal API handler with the shared middy middleware chain (logger
 * context injection + tracer). Set `jsonBody: false` for routes with no request
 * body (GET/DELETE) so the JSON body parser is not attached.
 *
 * middy is loaded via `dynamicImport` because it is ESM-only and these handlers
 * are compiled to CommonJS; that is the one place the interop is needed, so it
 * lives here rather than being repeated per handler module. The imported modules
 * are cached at module scope, so only a cold invocation pays for resolution.
 */
export function wrapWithMiddy(
  handler: RouteHandler,
  logger: Logger,
  tracer: Tracer,
  options: { jsonBody?: boolean } = {},
): RouteHandler {
  const { jsonBody = true } = options;
  // Compose the middy chain once per container (on the first invocation, once the
  // ESM interop has resolved) and reuse it on warm invocations, rather than
  // re-composing per request. handler/logger/tracer/jsonBody are fixed for this
  // route, so the composed handler is stable.
  let composed: RouteHandler | undefined;
  return async (event, context) => {
    if (!composed) {
      const { default: middy } = await loadMiddyCore();
      const chain = middy(handler).use(injectLambdaContext(logger)).use(captureLambdaHandler(tracer));

      if (jsonBody) {
        const { default: httpJsonBodyParser } = await loadHttpJsonBodyParser();
        chain.use(httpJsonBodyParser());
      }
      composed = chain;
    }

    return composed(event, context);
  };
}
