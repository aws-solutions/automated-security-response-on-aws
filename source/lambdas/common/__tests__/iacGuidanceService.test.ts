// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fc from 'fast-check';
import * as yaml from 'js-yaml';
import {
  IaCGuidanceService,
  type IaCFormat,
  type TemplateResolver,
  type TemplateType,
} from '../services/iacGuidanceService';
import { MockResolver } from '../services/mockResolver';

describe('IaCGuidanceService', () => {
  const mockResolver = new MockResolver();
  const service = new IaCGuidanceService(mockResolver);

  describe('input validation', () => {
    it('throws a descriptive error when controlId is an empty string', async () => {
      // GIVEN
      const emptyControlId = '';

      // WHEN
      const promise = service.getTemplates(emptyControlId, ['terraform']);

      // THEN
      await expect(promise).rejects.toThrow(/sanitizedControlId/i);
    });

    it('throws a descriptive error when controlId is undefined', async () => {
      // GIVEN
      const undefinedControlId = undefined as unknown as string;

      // WHEN
      const promise = service.getTemplates(undefinedControlId, ['terraform']);

      // THEN
      await expect(promise).rejects.toThrow(/sanitizedControlId/i);
    });

    it('throws an error listing valid values when formats contains an unrecognized format', async () => {
      // GIVEN
      const invalidFormats = ['not-a-format'] as unknown as IaCFormat[];

      // WHEN
      const promise = service.getTemplates('S3.1', invalidFormats);

      // THEN
      await expect(promise).rejects.toThrow(/not-a-format/);
      await expect(service.getTemplates('S3.1', invalidFormats)).rejects.toThrow(/cloudformation-yaml/);
    });

    it('returns an empty array when formats array is empty', async () => {
      // WHEN
      const results = await service.getTemplates('S3.1', []);

      // THEN
      expect(results).toEqual([]);
    });
  });

  describe('template resolution', () => {
    it('returns cloudformation YAML content for a known control', async () => {
      // WHEN
      const results = await service.getTemplates('S3.1', ['cloudformation-yaml']);

      // THEN
      expect(results).toHaveLength(1);
      expect(results[0].sanitizedControlId).toBe('S3.1');
      expect(results[0].format).toBe('cloudformation-yaml');
      expect(results[0].content).toContain('AWSTemplateFormatVersion');
    });

    it('returns JSON-converted content when cloudformation-json is requested', async () => {
      // WHEN
      const results = await service.getTemplates('S3.1', ['cloudformation-yaml', 'cloudformation-json']);

      // THEN
      const yamlResult = results.find((r) => r.format === 'cloudformation-yaml')!;
      const jsonResult = results.find((r) => r.format === 'cloudformation-json')!;

      const parsedJson = JSON.parse(jsonResult.content);
      const parsedYaml = yaml.load(yamlResult.content);
      expect(parsedJson).toEqual(parsedYaml);
    });

    it('returns all four formats for a known control', async () => {
      // GIVEN
      const allFormats: IaCFormat[] = ['cloudformation-yaml', 'cloudformation-json', 'terraform', 'cdk'];

      // WHEN
      const results = await service.getTemplates('S3.1', allFormats);

      // THEN
      expect(results).toHaveLength(4);
      const returnedFormats = results.map((r) => r.format);
      expect(returnedFormats).toEqual(expect.arrayContaining(allFormats));
      for (const result of results) {
        expect(result.sanitizedControlId).toBe('S3.1');
        expect(result.content.length).toBeGreaterThan(0);
      }
    });

    it('omits formats and logs warning when control ID is unknown', async () => {
      // GIVEN
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();

      // WHEN
      const results = await service.getTemplates('UNKNOWN.99', ['terraform', 'cdk']);

      // THEN
      expect(results).toHaveLength(0);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('UNKNOWN.99'));
      warnSpy.mockRestore();
    });

    it('propagates resolver errors to the caller', async () => {
      // GIVEN — a resolver that simulates a transient S3 error
      const errorResolver: TemplateResolver = {
        async resolve(): Promise<string | undefined> {
          throw new Error('S3 access denied');
        },
      };
      const errorService = new IaCGuidanceService(errorResolver);

      // WHEN
      const promise = errorService.getTemplates('S3.1', ['terraform']);

      // THEN
      await expect(promise).rejects.toThrow(/S3 access denied/);
    });
  });

  describe('single CloudFormation fetch optimization', () => {
    it('calls resolve once for cloudformation when both YAML and JSON are requested', async () => {
      // GIVEN — a spy resolver to count calls
      const yamlContent = 'AWSTemplateFormatVersion: "2010-09-09"\nResources: {}\n';
      const resolveSpy = jest.fn<Promise<string | undefined>, [string, TemplateType]>().mockResolvedValue(yamlContent);
      const spyService = new IaCGuidanceService({ resolve: resolveSpy });

      // WHEN
      const results = await spyService.getTemplates('S3.1', ['cloudformation-yaml', 'cloudformation-json']);

      // THEN
      expect(results).toHaveLength(2);
      const cloudformationCalls = resolveSpy.mock.calls.filter(([, templateType]) => templateType === 'cloudformation');
      expect(cloudformationCalls).toHaveLength(1);
    });
  });

  // Feature: iac-guidance-service, Property 1: Format resolution returns correct results
  // Validates: Requirements 1.1, 2.1, 3.1, 5.1, 6.2, 7.2
  describe('Property 1: Format resolution returns correct results', () => {
    const allFormats: IaCFormat[] = ['cloudformation-yaml', 'cloudformation-json', 'terraform', 'cdk'];

    const formatToTemplateType: Record<IaCFormat, TemplateType> = {
      'cloudformation-yaml': 'cloudformation',
      'cloudformation-json': 'cloudformation',
      terraform: 'terraform',
      cdk: 'cdk',
    };

    it('returns exactly one TemplateResult per requested format that the resolver has content for', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1 }),
          fc.subarray(allFormats, { minLength: 1 }),
          fc.record({
            cloudformation: fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
            terraform: fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
            cdk: fc.option(fc.string({ minLength: 1 }), { nil: undefined }),
          }),
          async (controlId, requestedFormats, resolverContent) => {
            // Ensure cloudformation content is valid YAML when cloudformation-json is requested
            if (requestedFormats.includes('cloudformation-json') && resolverContent.cloudformation !== undefined) {
              resolverContent.cloudformation = yaml.dump({ key: resolverContent.cloudformation });
            }

            const resolver: TemplateResolver = {
              async resolve(_controlId: string, templateType: TemplateType): Promise<string | undefined> {
                return resolverContent[templateType];
              },
            };

            const propertyService = new IaCGuidanceService(resolver);
            const warnSpy = jest.spyOn(console, 'warn').mockImplementation();

            const results = await propertyService.getTemplates(controlId, requestedFormats);

            const expectedFormats = requestedFormats.filter((format) => {
              const templateType = formatToTemplateType[format];
              return resolverContent[templateType] !== undefined;
            });

            expect(results).toHaveLength(expectedFormats.length);

            for (const result of results) {
              expect(result.sanitizedControlId).toBe(controlId);
              expect(requestedFormats).toContain(result.format);

              if (result.format === 'cloudformation-json') {
                expect(() => JSON.parse(result.content)).not.toThrow();
              } else {
                const templateType = formatToTemplateType[result.format];
                expect(result.content).toBe(resolverContent[templateType]);
              }
            }

            const resultFormats = results.map((r) => r.format);
            expect(new Set(resultFormats).size).toBe(resultFormats.length);

            warnSpy.mockRestore();
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
