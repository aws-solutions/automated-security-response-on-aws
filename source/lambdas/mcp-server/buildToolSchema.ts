// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Builds `toolSchema.json` — the tool list the AgentCore Gateway advertises — from the
 * schemas the MCP Lambda actually validates (`TOOL_INPUT_SCHEMAS`).
 *
 * The file used to be maintained by hand, and had drifted from the code on 14 of 28 tools.
 * Nine advertised no inputs beyond `__authorizationHeader` while validating fields here, so
 * an agent reading `tools/list` could not learn what to send. Six of those had *required*
 * fields, which made them impossible to call at all — including `execute_finding_action`,
 * the only route to the Rollback capability.
 *
 * Tool **descriptions** are not generated: they are curated prose aimed at the model
 * choosing a tool, so they are carried over from the existing file and only the
 * `inputSchema` is derived. A tool with no description would be a authoring mistake, so
 * that is an error rather than a silent empty string.
 */

import * as z from 'zod';
import { TOOL_INPUT_SCHEMAS } from './mcpServerHandler';

/**
 * Injected by the gateway request interceptor, which is authoritative over it — a
 * caller-supplied value is always overwritten or deleted (see
 * `lib/mcp/mcp-interceptor-source.ts`). It stays advertised because the interceptor writes
 * it into the tool arguments, and AgentCore may drop arguments absent from the schema.
 */
const AUTHORIZATION_ARGUMENT = '__authorizationHeader';
const AUTHORIZATION_PROPERTY = {
  type: 'string',
  description: 'Internal: injected by gateway interceptor. Do not set manually.',
} as const;

/**
 * Collapse a discriminated union into a single object schema: the union of every branch's
 * properties, requiring only the fields every branch requires (in practice, the
 * discriminator).
 *
 * `deploy_runbook` and `drift_detection` are `z.discriminatedUnion`s, and
 * `z.toJSONSchema` renders those as a top-level `anyOf` with no `properties` of its own.
 * Advertising that verbatim is not an option: an AgentCore tool schema is a flat
 * object-shaped subset of JSON Schema, so the branches would be dropped and the tool would
 * advertise no inputs at all — which is exactly how `deploy_runbook` lost all 11 of its
 * documented arguments when this generator was first written.
 *
 * Flattening is also what the previous hand-written file did, so switching to generation
 * keeps those three entries the shape clients already see. Two things are lost, and both are
 * deliberate: a field required only within one branch is advertised as optional, and the
 * discriminator becomes an `enum` of every branch's value rather than binding the other
 * fields to the branch that value selects. The Lambda still enforces the real per-branch
 * contract and returns a validation error naming the missing or offending field. What must
 * NOT be lost is the set of valid discriminator values — see {@link mergeUnionProperty}.
 */
/**
 * Merge one property's definition across every union branch that declares it.
 *
 * A plain `Object.assign` over the branches is wrong for the discriminator: each branch
 * carries its own `const` for it, so the LAST branch silently became the only advertised
 * value. `deploy_runbook` advertised `action: { const: 'deploy' }` and the `register`
 * action was unreachable; `drift_detection` hid `push`/`execute`; `update_controls` hid
 * every operation but one. A client generating a call from the advertised schema reads the
 * discriminator as a fixed constant and cannot discover the other valid values — the same
 * "impossible to call" failure this generator exists to prevent.
 *
 * So the branches' literals are unioned into an `enum` instead. A single shared literal
 * stays a `const`, which is the stronger assertion. If any branch leaves the property
 * unconstrained, the merged property is left unconstrained too: narrowing to the literals
 * only some branches require would reject a value another branch accepts.
 *
 * Merging keys is only sound when the branches agree on `type`. `update_controls.data` used
 * to be `z.array(SecurityControlSchema)` under `update` but `z.uuid()` under the filter
 * operations, and combining those produced a self-contradictory `type: 'string'` carrying
 * `items` and `minItems` — a shape no value can satisfy, so the tool became uncallable.
 * AgentCore requires a single `type` per node, so a genuinely polymorphic property cannot
 * be advertised faithfully in a flat schema; the first branch's definition is kept whole
 * instead, which is at least self-consistent but still leaves the other branches
 * uncallable from the advertised schema. That is why `update_controls` no longer advertises
 * the API union at all — its tool schema (`UpdateControlsToolSchema`) gives the filter id its
 * own argument, and the proxy maps it to the API body. This fallback remains for any future
 * union that hits the same problem. The Lambda still validates the real per-branch contract
 * and names the offending field.
 */
function mergeUnionProperty(definitions: readonly Record<string, unknown>[]): Record<string, unknown> {
  const declaredTypes = new Set(definitions.map((definition) => definition.type));
  if (declaredTypes.size > 1) return { ...definitions[0] };

  const merged: Record<string, unknown> = {};
  for (const definition of definitions) Object.assign(merged, definition);

  const literalsOf = (definition: Record<string, unknown>): unknown[] => {
    if ('const' in definition) return [definition.const];
    if (Array.isArray(definition.enum)) return definition.enum as unknown[];
    return [];
  };

  if (definitions.some((definition) => literalsOf(definition).length === 0)) {
    delete merged.const;
    delete merged.enum;
    return merged;
  }

  const allowedValues = [...new Set(definitions.flatMap(literalsOf))];
  if (allowedValues.length > 1) {
    delete merged.const;
    merged.enum = allowedValues;
  }
  return merged;
}

function flattenUnion(node: Record<string, unknown>): Record<string, unknown> {
  const branches = (node.anyOf ?? node.oneOf) as Record<string, unknown>[] | undefined;
  if (!branches || branches.length === 0) return node;

  // Collect each property's definition from every branch that declares it, so the merge
  // below can see the branches disagree rather than overwriting them one by one.
  const definitionsByProperty = new Map<string, Record<string, unknown>[]>();
  for (const branch of branches) {
    const branchProperties = (branch.properties as Record<string, Record<string, unknown>>) ?? {};
    for (const [name, definition] of Object.entries(branchProperties)) {
      const existing = definitionsByProperty.get(name);
      if (existing) existing.push(definition);
      else definitionsByProperty.set(name, [definition]);
    }
  }
  const properties = Object.fromEntries(
    [...definitionsByProperty].map(([name, definitions]) => [name, mergeUnionProperty(definitions)]),
  );

  const firstBranchRequired = [...new Set((branches[0].required as string[] | undefined) ?? [])];
  const requiredSets = branches.map((branch) => new Set((branch.required as string[] | undefined) ?? []));
  const requiredInEveryBranch = firstBranchRequired.filter((name) => requiredSets.every((set) => set.has(name)));

  const flattened: Record<string, unknown> = { ...node, type: 'object', properties };
  delete flattened.anyOf;
  delete flattened.oneOf;
  if (requiredInEveryBranch.length > 0) flattened.required = requiredInEveryBranch;
  else delete flattened.required;

  return flattened;
}

/**
 * Merge an `allOf` intersection into a single object schema.
 *
 * `z.intersection` (`a.and(b)`) renders as a top-level `allOf` with no `properties`
 * of its own — the same problem `flattenUnion` solves for unions, and it reaches
 * the same dead end: AgentCore's tool schema is a flat object shape, so an
 * unmerged `allOf` advertises no inputs, and `toAgentCoreSchema` cannot even find
 * a `type` to emit.
 *
 * Merging is exact here rather than lossy, which is the difference from
 * `flattenUnion`: an intersection requires *every* branch to match, so the union
 * of the branches' properties and the union of their `required` is precisely what
 * the value must satisfy. `update_notification` needs this — its request schema is
 * `Create.and({ version })`, composed that way because the create schema carries
 * `.refine()`s and so is not a plain object that could be `.extend()`ed.
 */
function mergeIntersection(node: Record<string, unknown>): Record<string, unknown> {
  const branches = node.allOf as Record<string, unknown>[] | undefined;
  if (!branches || branches.length === 0) return node;

  const properties: Record<string, unknown> = {};
  const required = new Set<string>();
  for (const branch of branches) {
    const merged = mergeIntersection(branch);
    Object.assign(properties, (merged.properties as Record<string, unknown>) ?? {});
    for (const name of (merged.required as string[] | undefined) ?? []) required.add(name);
  }

  const flattened: Record<string, unknown> = { ...node, type: 'object', properties };
  delete flattened.allOf;
  if (required.size > 0) flattened.required = [...required];
  else delete flattened.required;

  return flattened;
}

/**
 * Normalize one schema node — and everything under it — into the shape AgentCore accepts.
 *
 * `CfnGatewayTarget.SchemaDefinitionProperty` makes **`type` mandatory on every node**, so a
 * node Zod emits without one fails template synthesis outright:
 *
 *     inputSchema: properties: element 'deliveryChannels': items: type: required but missing
 *
 * That is what a nested union produces — `create_notification.deliveryChannels` is an array
 * of channel variants, so its `items` was `{ anyOf: [...] }` with no `type`. Flattening only
 * the top level was not enough; unions have to be collapsed wherever they appear.
 *
 * Other JSON Schema keywords (`enum`, `minimum`, `maximum`, `additionalProperties`) are left
 * alone: the previously shipping hand-written file used all of them and deployed fine, so
 * AgentCore ignores what it does not model rather than rejecting it.
 */
function toAgentCoreSchema(node: Record<string, unknown>): Record<string, unknown> {
  // Intersections first: a branch of an `allOf` can itself be a union, so merging
  // the intersection is what exposes that union to `flattenUnion`.
  const flattened = flattenUnion(mergeIntersection(node));
  const normalized: Record<string, unknown> = { ...flattened };

  if (normalized.properties && typeof normalized.properties === 'object') {
    normalized.properties = Object.fromEntries(
      Object.entries(normalized.properties as Record<string, Record<string, unknown>>).map(([name, child]) => [
        name,
        toAgentCoreSchema(child),
      ]),
    );
  }

  if (normalized.items && typeof normalized.items === 'object') {
    normalized.items = toAgentCoreSchema(normalized.items as Record<string, unknown>);
  }

  // Last resort so synthesis cannot fail on a missing `type`: a node carrying properties is
  // an object, one carrying items is an array. Anything else would be a Zod construct this
  // generator has not been taught to convert, and guessing a scalar type there would
  // silently mis-advertise it — so fail loudly instead.
  if (typeof normalized.type !== 'string') {
    if (normalized.properties) normalized.type = 'object';
    else if (normalized.items) normalized.type = 'array';
    else {
      throw new Error(
        `Cannot express schema node as an AgentCore tool schema: no 'type' could be determined from ` +
          `keys [${Object.keys(normalized).join(', ')}]. AgentCore requires 'type' on every node.`,
      );
    }
  }

  return normalized;
}

export interface AdvertisedTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

/**
 * Convert one tool's Zod input schema to the JSON Schema the gateway advertises.
 *
 * `io: 'input'` matters: it emits the shape a caller sends, so a field with a Zod default
 * is optional rather than required. Without it, defaulted fields would be advertised as
 * mandatory and an agent would be forced to invent values the Lambda would have supplied.
 */
function toInputSchema(schema: z.ZodSchema): Record<string, unknown> {
  const converted = toAgentCoreSchema(
    z.toJSONSchema(schema, { io: 'input', target: 'draft-7' }) as Record<string, unknown>,
  );

  // Drop the dialect marker: it is meaningless inside an AgentCore tool schema and only
  // adds noise to the committed file's diff.
  delete converted.$schema;

  const properties = { ...((converted.properties as Record<string, unknown>) ?? {}) };
  properties[AUTHORIZATION_ARGUMENT] = { ...AUTHORIZATION_PROPERTY };

  const result: Record<string, unknown> = { ...converted, type: 'object', properties };

  // `required: []` is legal but noisy, and the previous hand-written file omitted the key
  // entirely for no-argument tools. Keep that shape so the switch to generation does not
  // churn every entry.
  const required = (converted.required as string[] | undefined)?.filter((name) => name !== AUTHORIZATION_ARGUMENT);
  if (required && required.length > 0) {
    result.required = required;
  } else {
    delete result.required;
  }

  return result;
}

/**
 * Rebuild the advertised tool list, preserving each tool's curated description.
 *
 * @param existingTools the currently committed `toolSchema.json` contents, read by the
 *   caller so this module needs no filesystem access (it runs in both a test and a script).
 * @throws when a tool is implemented but has no description to carry over, or when the
 *   committed file lists a tool the Lambda does not implement — either is a real
 *   inconsistency that should stop the build rather than produce a misleading file.
 */
export function buildToolSchema(existingTools: readonly AdvertisedTool[]): AdvertisedTool[] {
  const descriptions = new Map(existingTools.map((tool) => [tool.name, tool.description]));

  const orphaned = existingTools.filter((tool) => !(tool.name in TOOL_INPUT_SCHEMAS)).map((tool) => tool.name);
  if (orphaned.length > 0) {
    throw new Error(
      `toolSchema.json advertises tools the MCP Lambda does not implement: ${orphaned.join(', ')}. ` +
        'Remove them, or add a route for them in handler.ts.',
    );
  }

  return Object.entries(TOOL_INPUT_SCHEMAS)
    .map(([name, schema]) => {
      const description = descriptions.get(name);
      if (!description) {
        throw new Error(
          `Tool '${name}' is implemented but has no description in toolSchema.json. ` +
            'Add one — the description is what the model uses to choose the tool, so it cannot be generated.',
        );
      }
      return { name, description, inputSchema: toInputSchema(schema) };
    })
    .sort((left, right) => left.name.localeCompare(right.name));
}
