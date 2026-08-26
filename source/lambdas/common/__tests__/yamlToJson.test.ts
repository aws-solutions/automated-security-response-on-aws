// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as yaml from 'js-yaml';
import * as fc from 'fast-check';
import { yamlToJson } from '../utils/yamlToJson';

describe('yamlToJson', () => {
  describe('unit tests', () => {
    it('converts valid YAML to valid JSON', () => {
      const yamlContent = yaml.dump({
        AWSTemplateFormatVersion: '2010-09-09',
        Resources: { MyBucket: { Type: 'AWS::S3::Bucket' } },
      });
      const result = yamlToJson(yamlContent);
      const parsed = JSON.parse(result);

      expect(parsed).toEqual({
        AWSTemplateFormatVersion: '2010-09-09',
        Resources: { MyBucket: { Type: 'AWS::S3::Bucket' } },
      });
    });

    it('produces pretty-printed JSON with 2-space indentation', () => {
      const yamlContent = yaml.dump({ key: 'value' });
      const result = yamlToJson(yamlContent);

      expect(result).toBe(JSON.stringify({ key: 'value' }, null, 2));
    });

    it('throws on invalid YAML input', () => {
      const invalidYaml = '{{not: valid: yaml:::';

      expect(() => yamlToJson(invalidYaml)).toThrow();
    });
  });

  describe('CloudFormation intrinsic shorthand tags', () => {
    it('expands !Ref to its long-form { Ref } object', () => {
      const result = JSON.parse(yamlToJson('Value: !Ref MyResource'));

      expect(result).toEqual({ Value: { Ref: 'MyResource' } });
    });

    it('expands scalar !GetAtt to a two-element Fn::GetAtt array', () => {
      const result = JSON.parse(yamlToJson('Value: !GetAtt MyResource.Arn'));

      expect(result).toEqual({ Value: { 'Fn::GetAtt': ['MyResource', 'Arn'] } });
    });

    it('expands !Sub to Fn::Sub', () => {
      const result = JSON.parse(yamlToJson('Value: !Sub "arn:${AWS::Partition}:s3:::bucket"'));

      expect(result).toEqual({ Value: { 'Fn::Sub': 'arn:${AWS::Partition}:s3:::bucket' } });
    });
  });

  describe('template placeholders', () => {
    it('preserves a {camelCase} runtime token used as a resource logical ID', () => {
      const yamlContent = ['Resources:', '  {bucketName}:', '    Type: AWS::S3::Bucket'].join('\n');

      const result = JSON.parse(yamlToJson(yamlContent));

      expect(result).toEqual({ Resources: { '{bucketName}': { Type: 'AWS::S3::Bucket' } } });
    });

    it('preserves an <UPPER_CASE> customer placeholder in a scalar value', () => {
      const yamlContent = [
        'Resources:',
        '  {bucket}:',
        '    Properties:',
        '      Target: <ACCESS_LOGGING_BUCKET>',
      ].join('\n');

      const result = JSON.parse(yamlToJson(yamlContent));

      expect(result.Resources['{bucket}'].Properties.Target).toBe('<ACCESS_LOGGING_BUCKET>');
    });
  });

  // Feature: iac-guidance-service, Property 2: YAML-to-JSON round trip
  // **Validates: Requirements 4.3**
  describe('Property 2: YAML-to-JSON round trip', () => {
    const plainObjectArbitrary = fc.dictionary(
      fc.string(),
      fc.oneof(
        fc.string(),
        fc.integer(),
        fc.double({ noNaN: true, noDefaultInfinity: true }).filter((n) => !Object.is(n, -0)),
        fc.boolean(),
        fc.array(fc.oneof(fc.string(), fc.integer(), fc.boolean())),
        fc.dictionary(fc.string(), fc.oneof(fc.string(), fc.integer(), fc.boolean())),
      ),
    );

    it('round-trips any plain JS object through YAML dump → yamlToJson → JSON.parse', () => {
      fc.assert(
        fc.property(plainObjectArbitrary, (original) => {
          const yamlContent = yaml.dump(original);
          const jsonString = yamlToJson(yamlContent);
          const roundTripped = JSON.parse(jsonString);

          expect(roundTripped).toEqual(original);
        }),
        { numRuns: 100 },
      );
    });
  });
});
