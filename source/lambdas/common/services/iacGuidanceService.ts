// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { yamlToJson } from '../utils/yamlToJson';

export const IaCFormatSchema = z.enum(['cloudformation-yaml', 'cloudformation-json', 'terraform', 'cdk']);
export type IaCFormat = z.infer<typeof IaCFormatSchema>;

export type TemplateType = 'cloudformation' | 'terraform' | 'cdk';

export interface TemplateResult {
  sanitizedControlId: string;
  format: IaCFormat;
  content: string;
}

export interface TemplateResolver {
  /**
   * Resolves template content for a given control and template type.
   * @returns The template content string, or undefined if not found.
   * @throws On transient/unexpected errors (e.g., S3 access denied).
   */
  resolve(sanitizedControlId: string, templateType: TemplateType): Promise<string | undefined>;
}

const FORMAT_TO_TEMPLATE_TYPE: Record<IaCFormat, TemplateType> = {
  'cloudformation-yaml': 'cloudformation',
  'cloudformation-json': 'cloudformation',
  terraform: 'terraform',
  cdk: 'cdk',
};

export class IaCGuidanceService {
  constructor(private readonly resolver: TemplateResolver) {}

  async getTemplates(sanitizedControlId: string, formats: IaCFormat[]): Promise<TemplateResult[]> {
    // Validate inputs
    this.validateInputs(sanitizedControlId, formats);

    if (formats.length === 0) {
      return [];
    }

    // Fetch distinct template types concurrently — cloudformation is fetched once
    // even when both cloudformation-yaml and cloudformation-json are requested
    const resolvedContent = await this.fetchTemplates(sanitizedControlId, formats);

    // Assemble results, converting YAML→JSON for cloudformation-json
    return this.assembleResults(sanitizedControlId, formats, resolvedContent);
  }

  private validateInputs(sanitizedControlId: string, formats: IaCFormat[]): void {
    if (!sanitizedControlId) {
      throw new Error('sanitizedControlId is required');
    }

    for (const format of formats) {
      const result = IaCFormatSchema.safeParse(format);
      if (!result.success) {
        throw new Error(`Invalid IaC format "${format}". Valid formats: ${IaCFormatSchema.options.join(', ')}`);
      }
    }
  }

  private async fetchTemplates(sanitizedControlId: string, formats: IaCFormat[]): Promise<Map<TemplateType, string>> {
    const distinctTemplateTypes = [...new Set(formats.map((f) => FORMAT_TO_TEMPLATE_TYPE[f]))];

    const settlements = await Promise.allSettled(
      distinctTemplateTypes.map((templateType) => this.resolver.resolve(sanitizedControlId, templateType)),
    );

    const resolvedContent = new Map<TemplateType, string>();
    for (let i = 0; i < distinctTemplateTypes.length; i++) {
      const settlement = settlements[i];
      if (settlement.status === 'rejected') {
        throw settlement.reason;
      }
      if (settlement.value !== undefined) {
        resolvedContent.set(distinctTemplateTypes[i], settlement.value);
      }
    }

    return resolvedContent;
  }

  private assembleResults(
    sanitizedControlId: string,
    formats: IaCFormat[],
    resolvedContent: Map<TemplateType, string>,
  ): TemplateResult[] {
    const results: TemplateResult[] = [];

    for (const format of formats) {
      const templateType = FORMAT_TO_TEMPLATE_TYPE[format];
      const content = resolvedContent.get(templateType);

      if (content === undefined) {
        console.warn(
          `Template not found for controlId "${sanitizedControlId}", templateType "${templateType}" (format "${format}")`,
        );
        continue;
      }

      if (format === 'cloudformation-json') {
        try {
          results.push({
            sanitizedControlId,
            format,
            content: yamlToJson(content),
          });
        } catch (error) {
          throw new Error(
            `Failed to convert YAML to JSON for controlId "${sanitizedControlId}": ${(error as Error).message}`,
          );
        }
      } else {
        results.push({ sanitizedControlId, format, content });
      }
    }

    return results;
  }
}
