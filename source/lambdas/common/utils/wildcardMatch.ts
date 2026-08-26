// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Returns true when the current pattern character matches the current text character —
 * either via the single-character wildcard `?` or an exact literal match.
 */
function isCharacterMatch(pattern: string, patternIndex: number, text: string, textIndex: number): boolean {
  return patternIndex < pattern.length && (pattern[patternIndex] === '?' || pattern[patternIndex] === text[textIndex]);
}

/**
 * Returns true when the current pattern character is the multi-character wildcard `*`.
 */
function isStarWildcard(pattern: string, patternIndex: number): boolean {
  return patternIndex < pattern.length && pattern[patternIndex] === '*';
}

/**
 * Case-sensitive glob matcher supporting two metacharacters:
 *   - `*` matches any run of characters, including the empty string.
 *   - `?` matches exactly one character.
 *
 * Uses an iterative two-pointer algorithm with O(n * m) worst-case time and no regex
 * compilation, so adversarial patterns cannot trigger catastrophic backtracking (ReDoS).
 *
 * @param text    String to match against.
 * @param pattern Pattern that may contain `*` and `?` wildcards.
 * @returns `true` when `pattern` matches `text` entirely.
 */
export function wildcardMatch(text: string, pattern: string): boolean {
  let textIndex = 0;
  let patternIndex = 0;
  let lastStarPatternIndex = -1;
  let lastStarTextIndex = 0;

  while (textIndex < text.length) {
    if (isCharacterMatch(pattern, patternIndex, text, textIndex)) {
      textIndex++;
      patternIndex++;
    } else if (isStarWildcard(pattern, patternIndex)) {
      lastStarPatternIndex = patternIndex;
      lastStarTextIndex = textIndex;
      patternIndex++;
    } else if (lastStarPatternIndex === -1) {
      return false;
    } else {
      // Backtrack: advance the most recent '*' to consume one more text character.
      patternIndex = lastStarPatternIndex + 1;
      lastStarTextIndex++;
      textIndex = lastStarTextIndex;
    }
  }

  // Remaining pattern characters must all be trailing '*'.
  while (patternIndex < pattern.length && pattern[patternIndex] === '*') patternIndex++;
  return patternIndex === pattern.length;
}

/**
 * Minimum number of colon-separated segments a valid AWS ARN has:
 *   `arn:partition:service:region:account:resource` — six segments.
 */
const ARN_MIN_SEGMENTS = 6;

/**
 * The number of fixed prefix segments (everything before the final resource part).
 * Segments: `arn`, `partition`, `service`, `region`, `account`.
 */
const ARN_PREFIX_SEGMENT_COUNT = 5;

/**
 * Matches an AWS resource ARN against a wildcard pattern using the semantics the solution
 * exposes to users who author resource filters:
 *
 *   1. Both strings must contain at least six colon-separated segments.
 *   2. The first five segments are compared segment-by-segment; each pattern segment must
 *      be `*` (whole-segment wildcard) or an exact literal match.
 *   3. The resource part (segment 5+, rejoined with colons) is compared with full wildcard
 *      semantics using {@link wildcardMatch}.
 *
 * Case-sensitive, because AWS resource identifiers (especially S3 object keys) are.
 *
 * @param arn     Concrete resource ARN from the event.
 * @param pattern ARN-shaped pattern, possibly containing `*` or `?`.
 * @returns `true` when the pattern matches the ARN under the rules above.
 */
export function arnMatchesPattern(arn: string, pattern: string): boolean {
  const arnParts = arn.split(':');
  const patternParts = pattern.split(':');
  if (arnParts.length < ARN_MIN_SEGMENTS || patternParts.length < ARN_MIN_SEGMENTS) return false;

  for (let i = 0; i < ARN_PREFIX_SEGMENT_COUNT; i++) {
    if (patternParts[i] !== '*' && patternParts[i] !== arnParts[i]) return false;
  }

  const resource = arnParts.slice(ARN_PREFIX_SEGMENT_COUNT).join(':');
  const resourcePattern = patternParts.slice(ARN_PREFIX_SEGMENT_COUNT).join(':');
  return wildcardMatch(resource, resourcePattern);
}
