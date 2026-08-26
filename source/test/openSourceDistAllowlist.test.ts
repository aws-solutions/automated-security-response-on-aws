// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the validation logic in deployment/build-open-source-dist.sh, which
 * decides what leaves the internal repository for the public GitHub repository.
 *
 * These tests do not build an archive. buildspec.yml runs the real script over
 * the real tree before it runs the test suite, so a build that would publish a
 * bad archive has already failed by the time these run. Rebuilding here would
 * re-answer a question CI answered a minute earlier, at minutes per case.
 *
 * What the build cannot catch is a check that has silently stopped checking: an
 * empty FORBIDDEN_PATTERNS, or a comparison in check_allowlist_is_covered that
 * returns success for everything. Those are invisible in a green build, so they
 * are what these tests are for. Each check is called directly against a small
 * staging directory built for the case.
 *
 * The staging directories are synthetic on purpose. Asserting against a copy of
 * the working tree made the outcome depend on what the checkout happened to
 * contain, which is how these tests came to fail in CI while passing locally:
 * build-tools/bin/custom-build strips dot-directories, so the CI source
 * directory has no .kiro/ for a test to find.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SCRIPT_PATH = path.join(REPO_ROOT, 'deployment', 'build-open-source-dist.sh');

const temporaryDirectories: string[] = [];

interface CheckResult {
  exitCode: number;
  output: string;
}

/**
 * Source the script and run `shellCode` against the definitions it loads.
 *
 * The script guards its own `main` behind a BASH_SOURCE check, so sourcing loads
 * the path lists and check functions without building anything. Sourcing the real
 * file rather than restating its lists is the point: a test that copied
 * FORBIDDEN_PATTERNS would still pass after someone emptied the original.
 */
function runAgainstScript(shellCode: string): CheckResult {
  const script = `set -eu -o pipefail\nsource "${SCRIPT_PATH}"\n${shellCode}\n`;
  try {
    const output = execFileSync('bash', ['-c', script], {
      cwd: REPO_ROOT,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { exitCode: 0, output };
  } catch (error: unknown) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return {
      exitCode: failure.status ?? 1,
      output: (failure.stdout ?? '') + (failure.stderr ?? ''),
    };
  }
}

/** Read one of the script's arrays, so tests can assert on the real lists. */
function readScriptArray(arrayName: string): string[] {
  const result = runAgainstScript(`printf '%s\\n' "\${${arrayName}[@]}"`);
  expect(result.exitCode).toBe(0);
  return result.output.split('\n').filter((line) => line.length > 0);
}

/**
 * Build a staging directory containing exactly `relativePaths`, each as a file
 * with a parent directory. A trailing slash makes an empty directory instead.
 */
function createStagingDirectory(relativePaths: string[]): string {
  const stagingPath = fs.mkdtempSync(path.join(os.tmpdir(), 'asr-open-source-staging-'));
  temporaryDirectories.push(stagingPath);

  for (const relativePath of relativePaths) {
    const absolutePath = path.join(stagingPath, relativePath);
    if (relativePath.endsWith('/')) {
      fs.mkdirSync(absolutePath, { recursive: true });
      continue;
    }
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, 'staged\n');
  }

  return stagingPath;
}

/** A staging directory holding every file the script requires, and nothing else. */
function createValidStagingDirectory(): string {
  return createStagingDirectory(readScriptArray('REQUIRED_FILES'));
}

afterAll(() => {
  for (const directory of temporaryDirectories) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('build-open-source-dist.sh', () => {
  describe('check_allowlist_is_covered', () => {
    test('passes for the allowlist the script actually ships', () => {
      // GIVEN the real PUBLISHED_PATHS and REQUIRED_FILES
      // WHEN the coverage check runs
      const result = runAgainstScript('check_allowlist_is_covered');

      // THEN every published path is vouched for by a required file
      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    test('fails when a published path has no required file to vouch for it', () => {
      // GIVEN a published path with nothing under it in REQUIRED_FILES. Publishing
      // a path unvouched means dropping it later would ship a quietly incomplete
      // archive.
      // WHEN the coverage check runs
      const result = runAgainstScript('PUBLISHED_PATHS+=(Config)\ncheck_allowlist_is_covered');

      // THEN it names the offending path
      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('published path has no entry in REQUIRED_FILES: Config');
    });

    test('does not accept a required file whose name merely starts with the published path', () => {
      // GIVEN `docs/publishedX/...`, which shares a prefix with `docs/published`
      // but sits outside it. A prefix comparison without the `/` boundary would
      // wrongly treat this as coverage.
      // WHEN the coverage check runs over that path alone
      const result = runAgainstScript(
        'PUBLISHED_PATHS=(docs/published)\nREQUIRED_FILES=(docs/publishedX/file.md)\ncheck_allowlist_is_covered',
      );

      // THEN the near-miss does not count as vouching for it
      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('docs/published');
    });
  });

  describe('check_published_paths_exist', () => {
    test('passes in the repository root, where every allowlisted path exists', () => {
      const result = runAgainstScript('check_published_paths_exist');

      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    test('fails with an actionable message when an allowlisted path does not exist', () => {
      // tar reports a missing operand as one line among its own output, so the
      // script names the path itself.
      const result = runAgainstScript('PUBLISHED_PATHS=(no-such-path)\ncheck_published_paths_exist');

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('allowlisted path does not exist: no-such-path');
      expect(result.output).toContain('run from the repository root');
    });
  });

  describe('check_required_files_present', () => {
    test('passes when the staging directory holds every required file', () => {
      // GIVEN a staging directory built from REQUIRED_FILES itself
      const stagingPath = createValidStagingDirectory();

      // WHEN the check runs
      const result = runAgainstScript(`check_required_files_present "${stagingPath}"`);

      // THEN nothing is reported missing
      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    test('fails naming the required file that is missing', () => {
      // GIVEN a staging directory missing exactly one required file
      const requiredFiles = readScriptArray('REQUIRED_FILES');
      const omitted = 'source/package.json';
      expect(requiredFiles).toContain(omitted);
      const stagingPath = createStagingDirectory(requiredFiles.filter((file) => file !== omitted));

      // WHEN the check runs
      const result = runAgainstScript(`check_required_files_present "${stagingPath}"`);

      // THEN the omission fails the build rather than shipping a smaller archive
      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain(`required file missing from open-source archive: ${omitted}`);
    });
  });

  describe('check_excluded_paths_absent', () => {
    test('passes when no excluded path was staged', () => {
      const stagingPath = createValidStagingDirectory();

      const result = runAgainstScript(`check_excluded_paths_absent "${stagingPath}"`);

      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    test('fails when a file inside a published tree is staged despite being excluded', () => {
      // source/test/buildspec.test.ts exercises the internal buildspec.yml, so it
      // sits inside a published tree but must not be published.
      const excludedPaths = readScriptArray('EXCLUDED_PATHS');
      expect(excludedPaths.length).toBeGreaterThan(0);
      const stagingPath = createStagingDirectory([...readScriptArray('REQUIRED_FILES'), excludedPaths[0]]);

      const result = runAgainstScript(`check_excluded_paths_absent "${stagingPath}"`);

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain(`excluded path present in open-source archive: ${excludedPaths[0]}`);
    });
  });

  describe('check_no_internal_paths', () => {
    test('passes for a staging directory holding only published files', () => {
      const stagingPath = createValidStagingDirectory();

      const result = runAgainstScript(`check_no_internal_paths "${stagingPath}"`);

      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    /**
     * One case per class of internal path. These are the leaks the check exists
     * to stop, and planting them is what proves the patterns still match: the
     * assertions above would pass just as well against an empty pattern list.
     */
    test.each([
      ['internal agent tooling', '.kiro/steering/check.md'],
      ['harness configuration', '.claude/settings.json'],
      ['the internal build wrapper', 'build-tools/bin/custom-build'],
      ['internal agent instructions', 'AGENTS.md'],
      ['the Brazil config', 'Config'],
      ['the internal buildspec', 'buildspec.yml'],
      ['load tests', 'loadtests/run.ts'],
      ['a dependency tree the prune list should have removed', 'source/node_modules/left-pad/index.js'],
      ['cdk synth output', 'source/playbooks/SC/cdk.out/SCStack.template.json'],
      ['a python cache', 'source/__pycache__/module.cpython-311.pyc'],
    ])('fails when the archive would contain %s', (_label, internalPath) => {
      // GIVEN a staging directory that is valid except for one internal path
      const stagingPath = createStagingDirectory([...readScriptArray('REQUIRED_FILES'), internalPath]);

      // WHEN the check runs
      const result = runAgainstScript(`check_no_internal_paths "${stagingPath}"`);

      // THEN the leak is caught and named
      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('internal path present in open-source archive');
      expect(result.output).toContain(internalPath);
    });

    test('detects internal tooling nested deep inside a published tree', () => {
      // source/ is published as a whole tree, so a pattern anchored to the
      // repository root would miss this. Anywhere-matching is the property here.
      const stagingPath = createStagingDirectory([...readScriptArray('REQUIRED_FILES'), 'source/lib/.kiro/notes.md']);

      const result = runAgainstScript(`check_no_internal_paths "${stagingPath}"`);

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('source/lib/.kiro');
    });

    test('reports how many paths matched, without listing a whole leaked tree', () => {
      // A leaked dependency tree is tens of thousands of paths; the message has to
      // stay readable in a build log.
      const dependencyFiles = Array.from(
        { length: 12 },
        (_unused, index) => `source/node_modules/pkg-${index}/index.js`,
      );
      const stagingPath = createStagingDirectory([...readScriptArray('REQUIRED_FILES'), ...dependencyFiles]);

      const result = runAgainstScript(`check_no_internal_paths "${stagingPath}"`);

      expect(result.exitCode).not.toBe(0);
      // 12 files plus the 12 parent directories and node_modules itself.
      expect(result.output).toContain('25 match(es)');
      const reportedPaths = result.output.split('\n').filter((line) => line.includes('source/node_modules/pkg-'));
      expect(reportedPaths.length).toBeLessThanOrEqual(5);
    });
  });

  describe('check_docs_are_internal_by_default', () => {
    test('passes when docs/published is the only documentation staged', () => {
      const stagingPath = createStagingDirectory([...readScriptArray('REQUIRED_FILES'), 'docs/published/guide.md']);

      const result = runAgainstScript(`check_docs_are_internal_by_default "${stagingPath}"`);

      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    test('fails when documentation outside docs/published/ is staged', () => {
      // Documentation is internal by default; publishing it means moving it into
      // docs/published/, so that links resolve the same in both repositories.
      const stagingPath = createStagingDirectory([
        ...readScriptArray('REQUIRED_FILES'),
        'docs/adr/0001-type-safety.md',
      ]);

      const result = runAgainstScript(`check_docs_are_internal_by_default "${stagingPath}"`);

      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('only docs/published/ may be published');
      expect(result.output).toContain('docs/adr');
    });

    test('passes when the archive has no docs directory at all', () => {
      // `find docs` on a missing directory must not fail the build by itself.
      const stagingPath = createStagingDirectory(['README.md']);

      const result = runAgainstScript(`check_docs_are_internal_by_default "${stagingPath}"`);

      expect(result.exitCode).toBe(0);
    });
  });

  describe('assert_archive_contents', () => {
    test('passes for a staging directory that satisfies every check', () => {
      const stagingPath = createStagingDirectory([...readScriptArray('REQUIRED_FILES'), 'docs/published/guide.md']);

      const result = runAgainstScript(`assert_archive_contents "${stagingPath}"`);

      expect(result.output).toBe('');
      expect(result.exitCode).toBe(0);
    });

    test('reports every failing check before refusing to publish', () => {
      // GIVEN a staging directory that trips several checks at once
      const stagingPath = createStagingDirectory([
        ...readScriptArray('REQUIRED_FILES').filter((file) => file !== 'tox.ini'),
        '.kiro/steering/check.md',
        'docs/adr/0001-type-safety.md',
      ]);

      // WHEN the aggregate assertion runs
      const result = runAgainstScript(`assert_archive_contents "${stagingPath}"`);

      // THEN one run surfaces all of them, rather than stopping at the first
      expect(result.exitCode).not.toBe(0);
      expect(result.output).toContain('required file missing from open-source archive: tox.ini');
      expect(result.output).toContain('internal path present in open-source archive');
      expect(result.output).toContain('only docs/published/ may be published');
      expect(result.output).toContain('nothing was published');
    });
  });

  describe('the path lists', () => {
    test('publishes no documentation path other than docs/published', () => {
      // The allowlist is the first gate; check_docs_are_internal_by_default is the
      // backstop. This keeps the two from drifting apart.
      const documentationPaths = readScriptArray('PUBLISHED_PATHS').filter((published) => published.startsWith('docs'));

      expect(documentationPaths).toEqual(['docs/published']);
    });

    test('prunes the dependency and build-output directories that would otherwise be published', () => {
      // source/ and deployment/ are published as whole trees, and in CI this script
      // runs after build-s3-dist.sh, so these are what the trees hold by then.
      const prunedNames = readScriptArray('PRUNED_NAMES');

      for (const buildOutput of ['node_modules', 'dist', 'cdk.out', '__pycache__', 'coverage', 'global-s3-assets']) {
        expect(prunedNames).toContain(buildOutput);
      }
    });
  });
});
