// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Amplify } from 'aws-amplify';
import { fetchAuthSession } from 'aws-amplify/auth';

async function makeRequest(apiName: string, path: string, method: string, init: RestApiOptions = {}): Promise<any> {
  const headers = await addAuthHeader(
    method === 'GET' || method === 'HEAD'
      ? init.headers
      : {
          ...init.headers,
          'Content-Type': 'application/json',
        },
  );

  const response = await fetch(baseUrl(apiName) + path + queryString(init.queryParams), {
    method,
    headers,
    ...(init.body && { body: JSON.stringify(init.body) }),
  });

  let responseBody;
  try {
    responseBody = await response.json();
  } catch (e) {
    responseBody = method === 'GET' ? null : {};
  }
  if (!response.ok) {
    const responseBodyMessage = responseBody.message;
    throw {
      response: {
        status: response.status,
        data: responseBodyMessage ?? responseBody,
      },
      message: responseBodyMessage || 'An unknown error occurred.',
    };
  }

  return responseBody;
}

/**
 * Adapter pattern.
 * API object implements the interface of amplify v5 API class, while using  amplify v6 methods under the hood,
 * so we don't have to change all usages of API.get, API.post, etc. across our app.
 */
export const API = {
  async get(apiName: string, path: string, init: RestApiOptions = {}): Promise<any> {
    return makeRequest(apiName, path, 'GET', init);
  },
  async head(apiName: string, path: string, init: RestApiOptions = {}): Promise<any> {
    return makeRequest(apiName, path, 'HEAD', init);
  },
  async post(apiName: string, path: string, init: RestApiOptions = {}): Promise<any> {
    return makeRequest(apiName, path, 'POST', init);
  },
  async put(apiName: string, path: string, init: RestApiOptions = {}): Promise<any> {
    return makeRequest(apiName, path, 'PUT', init);
  },
  async patch(apiName: string, path: string, init: RestApiOptions = {}): Promise<any> {
    return makeRequest(apiName, path, 'PATCH', init);
  },
  async del(apiName: string, path: string, init: RestApiOptions = {}): Promise<any> {
    return makeRequest(apiName, path, 'DELETE', init);
  },
};

function baseUrl(apiName: string): string {
  const apiConfigs = Amplify.getConfig().API?.REST;
  const endpoint = apiConfigs?.[apiName];
  if (!endpoint) {
    throw new Error(`API ${apiName} not found in Amplify config`);
  }
  return endpoint.endpoint;
}

export type RestApiOptions = {
  headers?: Record<string, string>;
  queryParams?: Record<string, string>;
  body?: any;
};

async function addAuthHeader(headers?: Record<string, string>) {
  const session = await fetchAuthSession();
  const accessToken = session.tokens?.accessToken?.toString();

  return {
    ...headers,
    // if ApiGateway methods have authorizationScopes defined, use accessToken with scopes. otherwise use idToken
    Authorization: `Bearer ${accessToken}`,
  };
}

function queryString(queryParams: Record<string, string> | undefined) {
  if (!queryParams || !Object.entries(queryParams).length) return '';
  const queryString = new URLSearchParams(queryParams).toString();
  return `?${queryString}`;
}
