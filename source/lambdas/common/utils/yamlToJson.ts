// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as yaml from 'js-yaml';

// CloudFormation templates use intrinsic-function shorthand tags (e.g. `!Ref`, `!GetAtt`,
// `!Sub`) that the default js-yaml schema rejects as unknown tags. Converting these to JSON
// requires teaching the parser to expand each tag to its long-form object representation
// (`!Ref X` -> `{ "Ref": "X" }`, `!GetAtt A.B` -> `{ "Fn::GetAtt": ["A", "B"] }`).

// Intrinsics whose JSON key is prefixed with `Fn::`. `!Ref`/`!Condition` are handled
// separately because their JSON keys carry no prefix.
const FN_INTRINSICS = [
  'Base64',
  'Cidr',
  'FindInMap',
  'GetAZs',
  'ImportValue',
  'Join',
  'Select',
  'Split',
  'Sub',
  'Transform',
  'And',
  'Equals',
  'If',
  'Not',
  'Or',
];

// A tag can appear in scalar (`!Sub "x"`), sequence (`!Join [...]`), or mapping
// (`!FindInMap {...}`) position — register all three so any usage resolves.
function tagTypes(tag: string, jsonKey: string): yaml.Type[] {
  return (['scalar', 'sequence', 'mapping'] as const).map(
    (kind) =>
      new yaml.Type(tag, { kind, construct: (data: unknown): Record<string, unknown> => ({ [jsonKey]: data }) }),
  );
}

// `!GetAtt Resource.Attribute` (scalar) expands to a two-element array; the sequence form
// (`!GetAtt [Resource, Attribute]`) is already an array.
const getAttTypes: yaml.Type[] = (['scalar', 'sequence'] as const).map(
  (kind) =>
    new yaml.Type('!GetAtt', {
      kind,
      construct: (data: unknown): { 'Fn::GetAtt': string[] } => {
        if (Array.isArray(data)) {
          return { 'Fn::GetAtt': data.map(String) };
        }
        const text = String(data);
        const dot = text.indexOf('.');
        return { 'Fn::GetAtt': dot === -1 ? [text] : [text.slice(0, dot), text.slice(dot + 1)] };
      },
    }),
);

const cloudFormationSchema = yaml.DEFAULT_SCHEMA.extend([
  ...tagTypes('!Ref', 'Ref'),
  ...tagTypes('!Condition', 'Condition'),
  ...getAttTypes,
  ...FN_INTRINSICS.flatMap((name) => tagTypes(`!${name}`, `Fn::${name}`)),
]);

// The `{camelCase}` runtime-token placeholders are also valid YAML flow-mapping syntax, so a
// resource logical ID like `{bucketName}:` would otherwise parse to a nested object instead of
// a string key. Swap the braces of placeholder-shaped tokens (a brace pair wrapping a run of
// identifier characters) to reserved private-use codepoints before parsing, and restore them in
// the output. Only the braces are swapped — the captured identifier is left in place — so the
// transform is unambiguously reversible. Genuine YAML flow mappings (`{}`, `{ a: 1 }`) contain
// no such identifier-only token and are left untouched. `<UPPER_CASE>` customer placeholders are
// valid YAML plain scalars and need no special handling.
const OPEN_BRACE_SENTINEL = '\uE000';
const CLOSE_BRACE_SENTINEL = '\uE001';
const PLACEHOLDER_TOKEN = /\{([A-Za-z0-9]+)\}/g;

const encodePlaceholderBraces = (text: string): string =>
  text.replaceAll(PLACEHOLDER_TOKEN, `${OPEN_BRACE_SENTINEL}$1${CLOSE_BRACE_SENTINEL}`);
const decodePlaceholderBraces = (text: string): string =>
  text.replaceAll(OPEN_BRACE_SENTINEL, '{').replaceAll(CLOSE_BRACE_SENTINEL, '}');

export function yamlToJson(yamlContent: string): string {
  const parsed: unknown = yaml.load(encodePlaceholderBraces(yamlContent), { schema: cloudFormationSchema });
  if (parsed === undefined) {
    return 'null';
  }
  return decodePlaceholderBraces(JSON.stringify(parsed, null, 2));
}
