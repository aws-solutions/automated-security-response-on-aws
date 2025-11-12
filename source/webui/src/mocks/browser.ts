// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Amplify } from 'aws-amplify';

/**
 * This function enables mock-service-worker (msw) in the browser, so you can do local frontend development against the mock handlers.
 *
 * Only if aws-exports.json file is NOT present or does NOT contain the API endpoint config, msw will be enabled.
 * If the API config is present, requests will be sent to the API.
 */
export async function startMockServer(apiEndpoint: string) {
  // if apiEndpoint is provided from aws-exports.json, do not enable mocking
  const isBackendConfigured = !!apiEndpoint;
  if (isBackendConfigured) {
    console.log('🚫 MSW disabled - Backend API endpoint configured:', apiEndpoint);
    return Promise.resolve();
  }

  console.log('🔧 MSW enabled - No backend API endpoint found, using mocks');

  const { setupWorker } = await import('msw/browser');
  const { handlers } = await import('./handlers');

  const worker = setupWorker(...handlers(apiEndpoint));
  // `worker.start()` returns a Promise that resolves
  // once the Service Worker is up and ready to intercept requests.
  return worker.start({
    onUnhandledRequest(request, print) {
      // Print MSW unhandled request warning, to detect requests that are not handled by MSW
      print.warning();
    },
  });
}
