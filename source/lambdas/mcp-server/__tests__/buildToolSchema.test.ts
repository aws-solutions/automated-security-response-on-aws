// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as z from 'zod';
import { AdvertisedTool, buildToolSchema } from '../buildToolSchema';
import { TOOL_INPUT_SCHEMAS } from '../mcpServerHandler';

const TOOL_SCHEMA_PATH = join(__dirname, '..', 'toolSchema.json');
const committed: AdvertisedTool[] = JSON.parse(readFileSync(TOOL_SCHEMA_PATH, 'utf8'));

const inputsOf = (tool: AdvertisedTool) =>
  Object.keys(tool.inputSchema.properties as Record<string, unknown>).filter(
    (name) => name !== '__authorizationHeader',
  );
const byName = (tools: readonly AdvertisedTool[], name: string) => tools.find((tool) => tool.name === name);

describe('toolSchema.json is generated from the schemas the Lambda validates', () => {
  it('matches what buildToolSchema produces, so the advertised inputs cannot drift', () => {
    // This is the guard that matters. The file was hand-maintained and had drifted on 14 of
    // 28 tools; regenerate with `npm run build:tool-schema` when a tool's schema changes.
    expect(buildToolSchema(committed)).toEqual(committed);
  });

  it('advertises every implemented tool and nothing else', () => {
    expect(committed.map((tool) => tool.name).sort()).toEqual(Object.keys(TOOL_INPUT_SCHEMAS).sort());
  });

  it('advertises every required field, so no tool can be impossible to call', () => {
    // The regression this locks down: a required field the Lambda enforces but the gateway
    // never advertises makes the tool unusable — the agent cannot know to send it.
    for (const tool of committed) {
      const required = (tool.inputSchema.required as string[] | undefined) ?? [];
      const advertised = Object.keys(tool.inputSchema.properties as Record<string, unknown>);
      expect(required.filter((name) => !advertised.includes(name))).toEqual([]);
    }
  });

  it('keeps Rollback reachable — execute_finding_action advertises its action and findings', () => {
    // Product feature C ("Safe Rollback") has no other route through MCP. Both fields are
    // required by the handler, and neither was advertised, so the tool could not be called.
    const tool = byName(committed, 'execute_finding_action');

    expect(inputsOf(tool!).sort()).toEqual(['actionType', 'findingIds', 'findingKeys']);
    expect(tool!.inputSchema.required).toEqual(['actionType', 'findingIds']);
    const actionType = (tool!.inputSchema.properties as Record<string, { enum?: string[] }>).actionType;
    expect(actionType.enum).toContain('Rollback');
  });

  it('flattens a discriminated union instead of dropping its branches', () => {
    // `z.toJSONSchema` renders a discriminatedUnion as a top-level `anyOf` with no
    // properties. Advertised verbatim, deploy_runbook would offer no arguments at all.
    const tool = byName(committed, 'deploy_runbook')!;

    expect(tool.inputSchema).not.toHaveProperty('anyOf');
    expect(tool.inputSchema.type).toBe('object');
    // Both union branches contribute: `register`-only and `deploy`-only fields coexist.
    expect(inputsOf(tool)).toEqual(expect.arrayContaining(['action', 'control_id', 'runbook_yaml', 'runbook_id']));
    // Only the fields every branch requires are advertised as required.
    expect(tool.inputSchema.required).toEqual(['action', 'control_id']);
  });

  // The regression: merging branches with Object.assign let the LAST branch's discriminator
  // `const` overwrite every earlier one, so deploy_runbook advertised `action: {const:
  // 'deploy'}` and the `register` action was unreachable — a client reading the schema could
  // not discover it existed. Every branch's value has to survive as an enum.
  it.each([
    ['deploy_runbook', 'action', ['register', 'deploy']],
    ['drift_detection', 'action', ['push', 'execute', 'status']],
    ['update_controls', 'operation', ['update', 'applyFilterToAll', 'removeFilterFromAll']],
  ])('%s advertises every valid %s, not just the last branch', (toolName, discriminator, expectedValues) => {
    const properties = byName(committed, toolName)!.inputSchema.properties as Record<
      string,
      { const?: string; enum?: string[] }
    >;
    const advertised = properties[discriminator];

    expect(advertised.const).toBeUndefined();
    expect(advertised.enum?.slice().sort()).toEqual([...expectedValues].sort());
  });

  it('keeps a single shared literal as a const rather than a one-value enum', () => {
    // A non-discriminator literal that every branch agrees on is a stronger assertion as
    // `const`, so the enum merge must not fire when the branches do not disagree.
    const merged = buildToolSchema(committed);
    const singleLiteralProperties = merged
      .flatMap((tool) => Object.values(tool.inputSchema.properties as Record<string, { enum?: unknown[] }>))
      .filter((property) => Array.isArray(property.enum) && property.enum.length === 1);

    expect(singleLiteralProperties).toEqual([]);
  });

  // Merging branch keys is only sound when the branches agree on `type`. `update_controls.data`
  // is an array under `update` and a uuid string under the filter operations; fusing them
  // produced `type: 'string'` carrying `items` and `minItems` — a shape no value satisfies, so
  // the tool was uncallable. No advertised node may mix keywords from incompatible types.
  it('advertises no node whose keywords contradict its declared type', () => {
    const contradictions: string[] = [];
    const walk = (node: unknown, path: string): void => {
      if (typeof node !== 'object' || node === null) return;
      const schemaNode = node as Record<string, unknown>;
      const declaredType = schemaNode.type;
      if (typeof declaredType === 'string') {
        if (declaredType !== 'array' && ('items' in schemaNode || 'minItems' in schemaNode)) {
          contradictions.push(`${path}: type '${declaredType}' with array keywords`);
        }
        if (declaredType !== 'string' && ('format' in schemaNode || 'pattern' in schemaNode)) {
          contradictions.push(`${path}: type '${declaredType}' with string keywords`);
        }
      }
      for (const [key, child] of Object.entries(schemaNode)) walk(child, `${path}.${key}`);
    };

    for (const tool of buildToolSchema(committed)) walk(tool.inputSchema, tool.name);

    expect(contradictions).toEqual([]);
  });

  it('advertises update_controls with one type per field, so every operation is constructible', () => {
    // The API body is a union in which `data` is an array for `update` and a uuid string for
    // the filter operations. AgentCore requires exactly one `type` per node, so that union
    // could never be advertised faithfully: the generator kept the array branch and a client
    // following the schema could not build a filter call at all. The tool therefore takes the
    // filter id as its own argument; neither branch-specific field may be advertised as
    // required, or the other operation becomes impossible again.
    const tool = byName(committed, 'update_controls')!.inputSchema;
    const properties = tool.properties as Record<string, Record<string, unknown>>;

    expect(properties.data.type).toBe('array');
    expect(properties.data).toHaveProperty('items');
    expect(properties.filterId.type).toBe('string');
    expect(properties.filterId).not.toHaveProperty('items');
    expect(properties.operation.enum).toEqual(
      expect.arrayContaining(['update', 'applyFilterToAll', 'removeFilterFromAll']),
    );
    expect(tool.required).toEqual(['operation']);
  });

  // The regression this guards: both tools relied on Zod `.passthrough()` to let the
  // request body through, which the generator rendered as `additionalProperties: {}`
  // — and AgentCore drops that keyword when it registers a tool. Clients then
  // received a closed schema naming only the path id, could send nothing else, and
  // both routes reject a call without the full record. Advertising the body is what
  // makes them callable, so it has to stay advertised.
  it.each([
    ['update_notification', 'id', ['name', 'enabled', 'notificationType', 'deliveryChannels']],
    ['update_filter', 'filterId', ['name', 'accountIds', 'version']],
  ])('%s advertises its request body, not just the path id', (toolName, pathParam, bodyFields) => {
    const tool = byName(buildToolSchema(committed), toolName)!;
    const properties = Object.keys(tool.inputSchema.properties as Record<string, unknown>);

    expect(properties).toContain(pathParam);
    for (const field of bodyFields) {
      expect(properties).toContain(field);
    }
    // The id is required alongside the body: the proxy lifts it into the URL.
    expect(tool.inputSchema.required).toContain(pathParam);
  });

  it('carries over curated descriptions rather than generating them', () => {
    for (const tool of buildToolSchema(committed)) {
      expect(tool.description.length).toBeGreaterThan(0);
      expect(tool.description).toBe(byName(committed, tool.name)!.description);
    }
  });

  it('refuses to build when an implemented tool has no description', () => {
    const missingOne = committed.filter((tool) => tool.name !== 'get_runbook');

    expect(() => buildToolSchema(missingOne)).toThrow(/get_runbook.*no description/s);
  });

  it('refuses to build when the file advertises a tool that is not implemented', () => {
    const withGhost = [
      ...committed,
      { name: 'ghost_tool', description: 'x', inputSchema: { type: 'object', properties: {} } },
    ];

    expect(() => buildToolSchema(withGhost)).toThrow(/does not implement: ghost_tool/);
  });

  it('requires exactly what the Zod schema requires on input', () => {
    // `io: 'input'` is what keeps these aligned: without it a field the Lambda would default
    // is advertised as required, forcing the agent to invent a value it should omit.
    for (const advertised of committed) {
      const converted = z.toJSONSchema(TOOL_INPUT_SCHEMAS[advertised.name], {
        io: 'input',
        target: 'draft-7',
      }) as { required?: string[]; anyOf?: unknown; oneOf?: unknown; allOf?: { required?: string[] }[] };
      // Unions are flattened, so their required list is narrower by design — covered above.
      // Zod renders a discriminated union as `anyOf` or `oneOf` depending on the branches,
      // so both have to be skipped here.
      if (converted.anyOf || converted.oneOf) continue;

      // An intersection (`a.and(b)`) puts its branches in `allOf` and carries no
      // top-level `required`, so comparing against that would assert the tool
      // requires nothing. Unlike a union the merge is exact — every branch must
      // match — so the expected list is the union of the branches', asserted rather
      // than skipped. `update_notification` and `update_filter` take this path.
      const expected = converted.allOf
        ? [...new Set(converted.allOf.flatMap((branch) => branch.required ?? []))]
        : (converted.required ?? []);

      expect(((advertised.inputSchema.required as string[] | undefined) ?? []).sort()).toEqual([...expected].sort());
    }
  });
});
