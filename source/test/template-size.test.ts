// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';

/**
 * CloudFormation template size limit for S3-stored templates (1 MB).
 * Using 1,000,000 bytes as a conservative limit.
 */
const CFN_TEMPLATE_SIZE_LIMIT = 1_000_000;

/**
 * Warning threshold at 90% of the limit to catch templates approaching the limit.
 */
const CFN_TEMPLATE_SIZE_WARNING_THRESHOLD = 900_000;

/**
 * Minimum template size to consider valid.
 * This solution uses SerializedNestedStackFactory which creates NestedStack objects
 * that reference external templates via S3 URL. CDK synthesizes these as empty "{}"
 * (2 bytes) since the actual content comes from pre-built templates at deployment time.
 * We filter these out as they're not real templates to validate.
 */
const MIN_VALID_TEMPLATE_SIZE = 100;

interface TemplateInfo {
  name: string;
  size: number;
  path: string;
}

/**
 * Finds all synthesized CloudFormation templates in a cdk.out directory.
 * Filters out empty stub files (< 100 bytes) created by SerializedNestedStackFactory
 * for nested stacks that reference external S3 templates.
 */
function findTemplatesInCdkOut(cdkOutPath: string): TemplateInfo[] {
  const templates: TemplateInfo[] = [];

  if (!fs.existsSync(cdkOutPath)) {
    return templates;
  }

  const files = fs.readdirSync(cdkOutPath);
  for (const file of files) {
    if (file.endsWith('.template.json')) {
      const filePath = path.join(cdkOutPath, file);
      const stats = fs.statSync(filePath);
      // Skip empty stub files from SerializedNestedStackFactory (synthesized as "{}")
      if (stats.size >= MIN_VALID_TEMPLATE_SIZE) {
        templates.push({
          name: file.replace('.template.json', ''),
          size: stats.size,
          path: filePath,
        });
      }
    }
  }

  return templates;
}

/**
 * Gets all cdk.out directories in the source tree.
 */
function getAllCdkOutDirectories(): string[] {
  const sourceDir = path.resolve(__dirname, '..');
  const cdkOutDirs: string[] = [];

  // Solution deploy
  const solutionDeployCdkOut = path.join(sourceDir, 'solution_deploy', 'cdk.out');
  if (fs.existsSync(solutionDeployCdkOut)) {
    cdkOutDirs.push(solutionDeployCdkOut);
  }

  // Playbooks
  const playbooksDir = path.join(sourceDir, 'playbooks');
  if (fs.existsSync(playbooksDir)) {
    const playbooks = fs.readdirSync(playbooksDir);
    for (const playbook of playbooks) {
      const playbookCdkOut = path.join(playbooksDir, playbook, 'cdk.out');
      if (fs.existsSync(playbookCdkOut)) {
        cdkOutDirs.push(playbookCdkOut);
      }
    }
  }

  // Blueprints
  const blueprintsDir = path.join(sourceDir, 'blueprints');
  if (fs.existsSync(blueprintsDir)) {
    const blueprints = fs.readdirSync(blueprintsDir);
    for (const blueprint of blueprints) {
      const blueprintCdkDir = path.join(blueprintsDir, blueprint, 'cdk');
      if (fs.existsSync(blueprintCdkDir)) {
        const blueprintCdkOut = path.join(blueprintCdkDir, 'cdk.out');
        if (fs.existsSync(blueprintCdkOut)) {
          cdkOutDirs.push(blueprintCdkOut);
        }
      }
    }
  }

  return cdkOutDirs;
}

describe('CloudFormation Template Size Validation', () => {
  let allTemplates: TemplateInfo[] = [];

  beforeAll(() => {
    const cdkOutDirs = getAllCdkOutDirectories();
    for (const cdkOutDir of cdkOutDirs) {
      const templates = findTemplatesInCdkOut(cdkOutDir);
      allTemplates = allTemplates.concat(templates);
    }
  });

  test('all synthesized templates should be found', () => {
    expect(allTemplates.length).toBeGreaterThan(0);
    console.log(`Found ${allTemplates.length} synthesized templates to validate`);
  });

  test('no template should exceed the CloudFormation size limit', () => {
    const oversizedTemplates: TemplateInfo[] = [];
    const warningTemplates: TemplateInfo[] = [];

    for (const template of allTemplates) {
      if (template.size > CFN_TEMPLATE_SIZE_LIMIT) {
        oversizedTemplates.push(template);
      } else if (template.size > CFN_TEMPLATE_SIZE_WARNING_THRESHOLD) {
        warningTemplates.push(template);
      }
    }

    // Log warnings for templates approaching the limit
    if (warningTemplates.length > 0) {
      console.warn('\n⚠️  Templates approaching size limit (>90%):');
      for (const template of warningTemplates) {
        const percentage = ((template.size / CFN_TEMPLATE_SIZE_LIMIT) * 100).toFixed(1);
        console.warn(`  - ${template.name}: ${template.size.toLocaleString()} bytes (${percentage}%)`);
      }
    }

    // Fail if any templates exceed the limit
    if (oversizedTemplates.length > 0) {
      const memberStackPattern = /^(SC|AFSBP|NIST80053|PCI321|CIS\d+)MemberStack\d*$/;
      const hasMemberStackFailure = oversizedTemplates.some((t) => memberStackPattern.test(t.name));

      const errorMessages = oversizedTemplates.map((t) => {
        const overBy = t.size - CFN_TEMPLATE_SIZE_LIMIT;
        return `  - ${t.name}: ${t.size.toLocaleString()} bytes (exceeds limit by ${overBy.toLocaleString()} bytes)`;
      });

      let suggestion = '\n\nConsider splitting large templates into nested stacks or reducing resource count.';
      if (hasMemberStackFailure) {
        suggestion =
          '\n\nFor playbook member stacks, reduce the memberStackLimits in source/cdk-config.json ' +
          'to split controls across more stacks (e.g., lower "sc", "nist", or "afsbp" values). After reducing memberStackLimits,' +
          'verify that the upgrade path still works and runbooks were not shifted between split stacks.';
      }

      // Force failure with descriptive message listing every oversized template.
      throw new Error(
        `\n❌ ${oversizedTemplates.length} template(s) exceed the CloudFormation size limit of ${CFN_TEMPLATE_SIZE_LIMIT.toLocaleString()} bytes:\n` +
          errorMessages.join('\n') +
          suggestion,
      );
    }

    // Real assertion for the passing path: no template may exceed the limit.
    expect(oversizedTemplates).toHaveLength(0);
  });

  test('generate template size report', () => {
    // Sort templates by size (largest first)
    const sortedTemplates = [...allTemplates].sort((a, b) => b.size - a.size);

    console.log('\n📊 Template Size Report (sorted by size):');
    console.log('─'.repeat(80));

    for (const template of sortedTemplates) {
      const percentage = ((template.size / CFN_TEMPLATE_SIZE_LIMIT) * 100).toFixed(1);
      const status =
        template.size > CFN_TEMPLATE_SIZE_LIMIT
          ? '❌ FAIL'
          : template.size > CFN_TEMPLATE_SIZE_WARNING_THRESHOLD
            ? '⚠️  WARN'
            : '✅ OK';

      console.log(`${status} ${template.name}`);
      console.log(`     Size: ${template.size.toLocaleString()} bytes (${percentage}% of limit)`);
    }

    console.log('─'.repeat(80));
    console.log(`Total templates: ${allTemplates.length}`);
    console.log(`Size limit: ${CFN_TEMPLATE_SIZE_LIMIT.toLocaleString()} bytes`);

    // The report is derived from every discovered template and must be ordered
    // largest-first; assert both so the test carries a meaningful check rather
    // than a tautology.
    expect(sortedTemplates).toHaveLength(allTemplates.length);
    for (let i = 1; i < sortedTemplates.length; i++) {
      expect(sortedTemplates[i - 1].size).toBeGreaterThanOrEqual(sortedTemplates[i].size);
    }
  });
});
