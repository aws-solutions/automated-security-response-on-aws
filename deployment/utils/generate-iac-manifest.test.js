// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const fc = require('fast-check');
const { discoverTemplates, generateManifest } = require('./generate-iac-manifest');

const RECOGNIZED_IAC_FORMATS = ['cloudformation', 'terraform', 'cdk'];

// --- Generators ---

/** Generates a control ID like S3.1, IAM.7, EC2.15 */
const controlIdArb = fc.tuple(
  fc.constantFrom('S3', 'IAM', 'EC2', 'RDS', 'ECS', 'ELB', 'KMS', 'SNS', 'SQS', 'DDB'),
  fc.integer({ min: 1, max: 99 }),
).map(([prefix, num]) => `${prefix}.${num}`);

/** Generates a recognized IaC format */
const iacFormatArb = fc.constantFrom(...RECOGNIZED_IAC_FORMATS);

/** Generates a non-empty file content string */
const fileContentArb = fc.string({ minLength: 1, maxLength: 200 });

/** Generates a single template entry: { controlId, iacFormat, content } */
const templateEntryArb = fc.tuple(controlIdArb, iacFormatArb, fileContentArb).map(
  ([controlId, iacFormat, content]) => ({ controlId, iacFormat, content }),
);

/** Generates a non-empty array of template entries with unique (controlId, iacFormat) pairs */
const templateSetArb = fc
  .uniqueArray(templateEntryArb, {
    minLength: 1,
    maxLength: 10,
    comparator: (a, b) => a.controlId === b.controlId && a.iacFormat === b.iacFormat,
  });

/** Generates a solution version string */
const versionArb = fc.tuple(
  fc.integer({ min: 1, max: 9 }),
  fc.integer({ min: 0, max: 99 }),
  fc.integer({ min: 0, max: 99 }),
).map(([major, minor, patch]) => `v${major}.${minor}.${patch}`);

// --- Helpers ---

const SUFFIX_MAP = {
  cloudformation: '.yaml',
  terraform: '.tf',
  cdk: '.ts',
};

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'iac-manifest-test-'));
}

function cleanupTempDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

/**
 * Writes template files into a temp directory following the {ControlId}/{iacFormat}/ structure.
 * Returns the temp dir path.
 */
function writeTemplateSet(tmpDir, templates) {
  for (const t of templates) {
    const suffix = SUFFIX_MAP[t.iacFormat];
    const dirPath = path.join(tmpDir, t.controlId, t.iacFormat);
    fs.mkdirSync(dirPath, { recursive: true });
    const filePath = path.join(dirPath, `remediation-${t.controlId}${suffix}`);
    fs.writeFileSync(filePath, t.content, 'utf8');
  }
}

// --- Property Tests ---

describe('Feature: build-script-template-packaging', () => {
  const NUM_RUNS = 100;

  // Property 1: Manifest structural validity
  // Validates: Requirements 3.1, 3.2, 3.3, 3.4
  test('Property 1: Manifest structural validity', () => {
    fc.assert(
      fc.property(templateSetArb, versionArb, (templates, version) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);
          const manifest = generateManifest(tmpDir, version);

          // Top-level fields
          expect(manifest.schemaVersion).toBe('1.0');
          expect(typeof manifest.generatedAt).toBe('string');
          expect(new Date(manifest.generatedAt).toISOString()).toBe(manifest.generatedAt);
          expect(manifest.solutionVersion).toBe(version);
          expect(Array.isArray(manifest.templates)).toBe(true);

          // Each template entry
          for (const entry of manifest.templates) {
            expect(typeof entry.controlId).toBe('string');
            expect(entry.controlId.length).toBeGreaterThan(0);
            expect(typeof entry.iacFormat).toBe('string');
            expect(RECOGNIZED_IAC_FORMATS).toContain(entry.iacFormat);
            expect(typeof entry.s3Key).toBe('string');
            expect(entry.s3Key.length).toBeGreaterThan(0);
            expect(typeof entry.sha256).toBe('string');
            expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
          }
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 2: Templates sorted by s3Key
  // Validates: Requirements 3.5
  test('Property 2: Templates sorted by s3Key', () => {
    fc.assert(
      fc.property(templateSetArb, versionArb, (templates, version) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);
          const manifest = generateManifest(tmpDir, version);

          for (let i = 1; i < manifest.templates.length; i++) {
            expect(
              manifest.templates[i - 1].s3Key < manifest.templates[i].s3Key,
            ).toBe(true);
          }
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 3: Checksum correctness
  // Validates: Requirements 4.1, 4.2, 4.3
  test('Property 3: Checksum correctness', () => {
    fc.assert(
      fc.property(templateSetArb, versionArb, (templates, version) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);
          const manifest = generateManifest(tmpDir, version);

          for (const entry of manifest.templates) {
            const filePath = path.join(tmpDir, entry.s3Key.split('/').join(path.sep));
            const content = fs.readFileSync(filePath);
            const expectedHash = crypto.createHash('sha256').update(content).digest('hex');
            expect(entry.sha256).toBe(expectedHash);
          }
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 4: Manifest self-exclusion
  // Validates: Requirements 5.3
  test('Property 4: Manifest self-exclusion', () => {
    fc.assert(
      fc.property(templateSetArb, versionArb, (templates, version) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);

          // Place a .metadata/manifest.json file in the target dir
          const metadataDir = path.join(tmpDir, '.metadata');
          fs.mkdirSync(metadataDir, { recursive: true });
          fs.writeFileSync(
            path.join(metadataDir, 'manifest.json'),
            JSON.stringify({ dummy: true }),
          );

          const manifest = generateManifest(tmpDir, version);

          for (const entry of manifest.templates) {
            expect(entry.s3Key).not.toContain('.metadata/manifest.json');
          }
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 5: Template discovery and classification
  // Validates: Requirements 7.1, 7.2, 7.3, 7.4
  test('Property 5: Template discovery and classification', () => {
    fc.assert(
      fc.property(templateSetArb, (templates) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);
          const discovered = discoverTemplates(tmpDir);

          for (const t of templates) {
            const suffix = SUFFIX_MAP[t.iacFormat];
            const expectedS3Key = `${t.controlId}/${t.iacFormat}/remediation-${t.controlId}${suffix}`;

            const match = discovered.find((d) => d.s3Key === expectedS3Key);
            expect(match).toBeDefined();
            expect(match.controlId).toBe(t.controlId);
            expect(match.iacFormat).toBe(t.iacFormat);
          }

          // Count should match
          expect(discovered.length).toBe(templates.length);
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 6: Non-template file exclusion
  // Validates: Requirements 7.5
  test('Property 6: Non-template file exclusion', () => {
    fc.assert(
      fc.property(templateSetArb, (templates) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);

          // Add non-template files: file directly under a control ID dir
          const firstControl = templates[0].controlId;
          fs.writeFileSync(path.join(tmpDir, firstControl, 'stray-file.txt'), 'stray');

          // Add file under .metadata/
          const metadataDir = path.join(tmpDir, '.metadata');
          fs.mkdirSync(metadataDir, { recursive: true });
          fs.writeFileSync(path.join(metadataDir, 'notes.txt'), 'notes');

          // Add file under an unrecognized format dir
          const badFormatDir = path.join(tmpDir, firstControl, 'ansible');
          fs.mkdirSync(badFormatDir, { recursive: true });
          fs.writeFileSync(path.join(badFormatDir, 'playbook.yml'), 'ansible');

          const discovered = discoverTemplates(tmpDir);
          const s3Keys = discovered.map((d) => d.s3Key);

          // None of the non-template files should appear
          for (const key of s3Keys) {
            expect(key).not.toContain('stray-file.txt');
            expect(key).not.toContain('.metadata');
            expect(key).not.toContain('ansible');
          }

          // Only the valid templates should be present
          expect(discovered.length).toBe(templates.length);
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 7: Build determinism
  // Validates: Requirements 9.1, 9.2, 9.3
  test('Property 7: Build determinism', () => {
    fc.assert(
      fc.property(templateSetArb, versionArb, (templates, version) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);

          const manifest1 = generateManifest(tmpDir, version);
          const manifest2 = generateManifest(tmpDir, version);

          // Strip generatedAt before comparison
          const { generatedAt: _g1, ...rest1 } = manifest1;
          const { generatedAt: _g2, ...rest2 } = manifest2;

          expect(rest1).toEqual(rest2);
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });

  // Property 8: Manifest JSON round-trip
  // Validates: Requirements 11.1, 11.2
  test('Property 8: Manifest JSON round-trip', () => {
    fc.assert(
      fc.property(templateSetArb, versionArb, (templates, version) => {
        const tmpDir = createTempDir();
        try {
          writeTemplateSet(tmpDir, templates);
          const manifest = generateManifest(tmpDir, version);

          const roundTripped = JSON.parse(JSON.stringify(manifest));
          expect(roundTripped).toEqual(manifest);
        } finally {
          cleanupTempDir(tmpDir);
        }
      }),
      { numRuns: NUM_RUNS },
    );
  });
});

// --- Unit Tests: CLI argument validation and edge cases ---

describe('CLI argument validation and edge cases', () => {
  const { execFileSync } = require('child_process');
  const scriptPath = path.join(__dirname, 'generate-iac-manifest.js');

  function runScript(args) {
    return execFileSync(process.execPath, [scriptPath, ...args], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  }

  function runScriptSafe(args) {
    try {
      const stdout = runScript(args);
      return { stdout, stderr: '', exitCode: 0 };
    } catch (err) {
      return { stdout: err.stdout || '', stderr: err.stderr || '', exitCode: err.status };
    }
  }

  // Validates: Requirement 6.4
  test('missing --target prints error and exits with code 1', () => {
    const result = runScriptSafe(['--output', '/tmp/out.json', '--version', 'v1.0.0']);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toMatch(/--target/);
  });

  // Validates: Requirement 6.5
  test('missing --output prints error and exits with code 1', () => {
    const result = runScriptSafe(['--target', '/tmp/some-dir', '--version', 'v1.0.0']);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toMatch(/--output/);
  });

  // Validates: Requirement 6.6
  test('missing --version prints error and exits with code 1', () => {
    const result = runScriptSafe(['--target', '/tmp/some-dir', '--output', '/tmp/out.json']);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toMatch(/--version/);
  });

  // Validates: Requirement 10.1
  test('empty target directory produces valid manifest with templates: []', () => {
    const tmpDir = createTempDir();
    try {
      const manifest = generateManifest(tmpDir, 'v1.0.0');
      expect(manifest.schemaVersion).toBe('1.0');
      expect(manifest.solutionVersion).toBe('v1.0.0');
      expect(manifest.templates).toEqual([]);
      expect(typeof manifest.generatedAt).toBe('string');
    } finally {
      cleanupTempDir(tmpDir);
    }
  });

  // Validates: Requirement 6.8
  test('summary output line contains template count and output path', () => {
    const tmpDir = createTempDir();
    const outputPath = path.join(tmpDir, '.metadata', 'manifest.json');
    try {
      const result = runScriptSafe([
        '--target', tmpDir,
        '--output', outputPath,
        '--version', 'v2.0.0',
      ]);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('0 templates');
      expect(result.stdout).toContain(outputPath);
    } finally {
      cleanupTempDir(tmpDir);
    }
  });
});
