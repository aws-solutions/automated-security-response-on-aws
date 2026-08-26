// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { wildcardMatch, arnMatchesPattern } from '../wildcardMatch';

describe('wildcardMatch', () => {
  describe('literal patterns (no wildcards)', () => {
    it('returns true when the pattern equals the text exactly', () => {
      expect(wildcardMatch('abc', 'abc')).toBe(true);
    });

    it('returns false when the pattern differs at any character', () => {
      expect(wildcardMatch('abc', 'abd')).toBe(false);
    });

    it('returns false when the pattern is a strict prefix of the text', () => {
      expect(wildcardMatch('abcdef', 'abc')).toBe(false);
    });

    it('returns false when the pattern is a strict suffix of the text', () => {
      expect(wildcardMatch('abcdef', 'def')).toBe(false);
    });

    it('is case-sensitive', () => {
      expect(wildcardMatch('abc', 'ABC')).toBe(false);
    });
  });

  describe('empty strings', () => {
    it('returns true when both pattern and text are empty', () => {
      expect(wildcardMatch('', '')).toBe(true);
    });

    it('returns false when the pattern is empty but the text is not', () => {
      expect(wildcardMatch('abc', '')).toBe(false);
    });

    it('returns false when the text is empty and the pattern has no wildcards', () => {
      expect(wildcardMatch('', 'abc')).toBe(false);
    });

    it('returns true when the text is empty and the pattern is a single star', () => {
      expect(wildcardMatch('', '*')).toBe(true);
    });

    it('returns true when the text is empty and the pattern is multiple stars', () => {
      expect(wildcardMatch('', '***')).toBe(true);
    });

    it('returns false when the text is empty and the pattern uses a question mark', () => {
      expect(wildcardMatch('', '?')).toBe(false);
    });
  });

  describe('? wildcard', () => {
    it('matches exactly one character', () => {
      expect(wildcardMatch('abc', 'a?c')).toBe(true);
    });

    it('does not match zero characters', () => {
      expect(wildcardMatch('ac', 'a?c')).toBe(false);
    });

    it('does not match two characters', () => {
      expect(wildcardMatch('abbc', 'a?c')).toBe(false);
    });

    it('works consecutively', () => {
      expect(wildcardMatch('abcd', 'a??d')).toBe(true);
      expect(wildcardMatch('ad', 'a??d')).toBe(false);
    });

    it('matches at the end of the pattern', () => {
      expect(wildcardMatch('abc', 'ab?')).toBe(true);
    });

    it('matches at the start of the pattern', () => {
      expect(wildcardMatch('abc', '?bc')).toBe(true);
    });
  });

  describe('* wildcard', () => {
    it('matches any single-character run', () => {
      expect(wildcardMatch('abc', 'a*c')).toBe(true);
    });

    it('matches an empty run', () => {
      expect(wildcardMatch('ac', 'a*c')).toBe(true);
    });

    it('matches a long run', () => {
      expect(wildcardMatch('aXYZc', 'a*c')).toBe(true);
    });

    it('matches a trailing run', () => {
      expect(wildcardMatch('aXYZ', 'a*')).toBe(true);
    });

    it('matches a leading run', () => {
      expect(wildcardMatch('XYZc', '*c')).toBe(true);
    });

    it('returns false when the literal tail does not match', () => {
      expect(wildcardMatch('aXYZd', 'a*c')).toBe(false);
    });

    it('collapses consecutive stars', () => {
      expect(wildcardMatch('abc', 'a**c')).toBe(true);
      expect(wildcardMatch('abc', 'a***c')).toBe(true);
    });

    it('a single star matches any text', () => {
      expect(wildcardMatch('abc', '*')).toBe(true);
      expect(wildcardMatch('', '*')).toBe(true);
      expect(wildcardMatch('any:resource:arn:with::colons', '*')).toBe(true);
    });
  });

  describe('combined * and ?', () => {
    it('mixes stars and question marks', () => {
      expect(wildcardMatch('abcd', 'a?*d')).toBe(true); // '?' = 'b', '*' = 'c'
      expect(wildcardMatch('ad', 'a?*d')).toBe(false); // '?' still requires one char
    });

    it('handles interleaved wildcards and literals', () => {
      expect(wildcardMatch('abcdef', 'a*c*e*')).toBe(true);
      expect(wildcardMatch('abxdyf', 'a*c*e*')).toBe(false);
    });
  });

  describe('ReDoS-resistance', () => {
    it('returns quickly for adversarial patterns against non-matching text', () => {
      // Classic "catastrophic backtracking" shape: many stars with interleaved literals that
      // never match the trailing literal. Must complete in sub-second wall time.
      const pattern = '*a*b*c*d*e*f*g*h*i*j*k*l*m*n*o*p';
      const text = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX';
      const start = Date.now();
      expect(wildcardMatch(text, pattern)).toBe(false);
      expect(Date.now() - start).toBeLessThan(1000);
    });

    it('returns quickly for long runs of stars', () => {
      const pattern = '*'.repeat(100) + 'X';
      const text = 'a'.repeat(1000);
      const start = Date.now();
      expect(wildcardMatch(text, pattern)).toBe(false);
      expect(Date.now() - start).toBeLessThan(1000);
    });
  });
});

describe('arnMatchesPattern', () => {
  const S3_OBJECT_ARN = 'arn:aws:s3:::my-bucket/path/to/key';
  const LAMBDA_ARN = 'arn:aws:lambda:us-east-1:123456789012:function:my-fn';

  describe('prefix segment rules', () => {
    it('matches when every fixed segment is an exact match', () => {
      expect(arnMatchesPattern(LAMBDA_ARN, 'arn:aws:lambda:us-east-1:123456789012:function:my-fn')).toBe(true);
    });

    it('allows a star in a fixed segment', () => {
      expect(arnMatchesPattern(LAMBDA_ARN, 'arn:aws:lambda:*:123456789012:function:my-fn')).toBe(true);
    });

    it('rejects partial wildcards inside a fixed segment', () => {
      // Pattern segment "us-east-*" is neither "*" nor an exact match → reject.
      expect(arnMatchesPattern(LAMBDA_ARN, 'arn:aws:lambda:us-east-*:123456789012:function:my-fn')).toBe(false);
    });

    it('rejects a different service', () => {
      expect(arnMatchesPattern(LAMBDA_ARN, 'arn:aws:ec2:us-east-1:123456789012:function:my-fn')).toBe(false);
    });

    it('rejects a different account', () => {
      expect(arnMatchesPattern(LAMBDA_ARN, 'arn:aws:lambda:us-east-1:999999999999:function:my-fn')).toBe(false);
    });
  });

  describe('resource segment rules', () => {
    it('matches the resource segment with a trailing star', () => {
      expect(arnMatchesPattern(S3_OBJECT_ARN, 'arn:aws:s3:::my-bucket/*')).toBe(true);
    });

    it('matches the resource segment with an interior star', () => {
      expect(arnMatchesPattern(S3_OBJECT_ARN, 'arn:aws:s3:::my-bucket/*/key')).toBe(true);
    });

    it('rejects when the resource-segment literal does not match', () => {
      expect(arnMatchesPattern(S3_OBJECT_ARN, 'arn:aws:s3:::other-bucket/*')).toBe(false);
    });

    it('preserves additional colons in the resource segment', () => {
      const sqsArnWithColons = 'arn:aws:sns:us-east-1:123456789012:topic:subsection';
      expect(arnMatchesPattern(sqsArnWithColons, 'arn:aws:sns:us-east-1:123456789012:topic:*')).toBe(true);
    });

    it('is case-sensitive on the resource segment', () => {
      expect(arnMatchesPattern(S3_OBJECT_ARN, 'arn:aws:s3:::MY-BUCKET/*')).toBe(false);
    });
  });

  describe('S3 bucket ARN patterns with slashes', () => {
    it('matches a bucket-level wildcard against an ARN containing object key path separators', () => {
      expect(arnMatchesPattern('arn:aws:s3:::my-bucket/folder/subfolder/file.txt', 'arn:aws:s3:::my-bucket/*')).toBe(
        true,
      );
    });

    it('matches a catch-all pattern against deeply nested S3 object keys', () => {
      expect(arnMatchesPattern('arn:aws:s3:::my-bucket/a/b/c/d/e/f/g.json', 'arn:aws:s3:::*')).toBe(true);
    });

    it('matches a prefix wildcard that spans multiple path segments', () => {
      expect(
        arnMatchesPattern('arn:aws:s3:::my-bucket/logs/2025/01/15/access.log', 'arn:aws:s3:::my-bucket/logs/*'),
      ).toBe(true);
    });

    it('matches an interior wildcard spanning path segments with a fixed suffix', () => {
      expect(
        arnMatchesPattern('arn:aws:s3:::my-bucket/logs/2025/01/15/access.log', 'arn:aws:s3:::my-bucket/*/access.log'),
      ).toBe(true);
    });

    it('rejects when the fixed suffix after the wildcard does not match', () => {
      expect(
        arnMatchesPattern('arn:aws:s3:::my-bucket/logs/2025/01/15/error.log', 'arn:aws:s3:::my-bucket/*/access.log'),
      ).toBe(false);
    });

    it('matches a pattern with wildcard bucket name and object key path', () => {
      expect(arnMatchesPattern('arn:aws:s3:::prod-data-bucket/exports/report.csv', 'arn:aws:s3:::prod-*')).toBe(true);
    });
  });

  describe('input validation', () => {
    it('rejects ARNs with fewer than six segments', () => {
      expect(arnMatchesPattern('arn:aws:lambda', 'arn:aws:lambda:*:*:*')).toBe(false);
    });

    it('rejects patterns with fewer than six segments', () => {
      expect(arnMatchesPattern(LAMBDA_ARN, 'arn:aws:lambda')).toBe(false);
    });

    it('rejects empty inputs', () => {
      expect(arnMatchesPattern('', 'arn:aws:lambda:*:*:*')).toBe(false);
      expect(arnMatchesPattern(LAMBDA_ARN, '')).toBe(false);
    });
  });
});
