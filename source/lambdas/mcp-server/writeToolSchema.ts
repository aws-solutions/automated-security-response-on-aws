// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Rewrites `toolSchema.json` from the schemas the MCP Lambda validates.
 *
 * Run with `npm run build:tool-schema` after changing any tool's input schema; the
 * `buildToolSchema` test fails until the committed file matches. Descriptions are preserved
 * from the existing file — edit them there.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { AdvertisedTool, buildToolSchema } from './buildToolSchema';

const toolSchemaPath = join(__dirname, 'toolSchema.json');
const existing: AdvertisedTool[] = JSON.parse(readFileSync(toolSchemaPath, 'utf8'));
const generated = buildToolSchema(existing);

writeFileSync(toolSchemaPath, `${JSON.stringify(generated, null, 2)}\n`);
console.info(`Wrote ${generated.length} tools to ${toolSchemaPath}`);
