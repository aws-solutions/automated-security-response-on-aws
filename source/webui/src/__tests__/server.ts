// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { setupServer } from 'msw/node';
import { handlers } from '../mocks/handlers.ts';

// configures a mock server for unit tests.
// call server.use() in test to set up handlers.
export const MOCK_SERVER_URL = 'http://localhost:3001/';
export const server = setupServer(...handlers(MOCK_SERVER_URL));
