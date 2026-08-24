// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for build-tools/bin/custom-build, which copies the working tree into
 * build/ to become the Brazil build artifact. That artifact is what CodeBuild
 * unpacks as its source directory, so a path missing here is missing from every
 * downstream build.
 *
 * The copy uses `rsync --exclude-from=.gitignore`, which is the subtlety worth
 * holding under test: rsync does not implement git's pattern language. It reads
 * a `!foo` line as a literal filename rather than as a re-inclusion, so
 * .gitignore's dot-directory rule drops every top-level dot-directory and the
 * `!` lines that keep some of them in git have no effect here. `.github` is
 * published to the public repository, so it has to be restored explicitly.
 *
 * The real rsync command is extracted from the script rather than restated, so
 * these tests cannot pass against a command the build no longer runs.
 *
 * Nothing here may read git state. In CI these tests run inside the copy this
 * script produces, which is a plain directory with no .git in it.
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CUSTOM_BUILD_PATH = path.join(REPO_ROOT, 'build-tools', 'bin', 'custom-build');

/**
 * Paths that must survive the copy. `.github` is in the open-source allowlist in
 * deployment/build-open-source-dist.sh, which fails the build when the path is
 * absent; mockServiceWorker.js is negated in .gitignore and so needs the same
 * explicit rescue.
 */
const REQUIRED_DEPLOYED_PATHS = [
  '.github/PULL_REQUEST_TEMPLATE.md',
  '.github/ISSUE_TEMPLATE/bug_report.md',
  'source/webui/public/mockServiceWorker.js',
];

/**
 * Files in the internal-only dot-directories that the dot-directory rule is there
 * to exclude. Asserted against the fixture tree, not the working tree — see
 * createDotDirectoryFixture.
 */
const INTERNAL_DOT_DIRECTORY_FILES = [
  '.kiro/steering/check.md',
  '.claude/settings.json',
  '.idea/workspace.xml',
  '.security-scan/findings.json',
];

/**
 * Planted alongside the internal dot-directories. If the rsync rules ever
 * excluded everything, the exclusion assertions would all pass; this one would
 * fail, so it is what tells the two apart.
 */
const CONTROL_FIXTURE_FILE = '.github/PULL_REQUEST_TEMPLATE.md';

const temporaryDirectories: string[] = [];

/**
 * Pull the rsync invocation out of custom-build's build|release branch.
 *
 * Anchoring on `rsync` alone would also match a future second copy, so the match
 * is required to be unique — otherwise the test could silently exercise the
 * wrong command.
 */
function parseRsyncCommand(): string {
  const script = fs.readFileSync(CUSTOM_BUILD_PATH, 'utf-8');
  const rsyncLines = script
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('rsync '));

  if (rsyncLines.length !== 1) {
    throw new Error(`Expected exactly 1 rsync command in build-tools/bin/custom-build, found ${rsyncLines.length}`);
  }

  return rsyncLines[0];
}

function createTemporaryDirectory(prefix: string): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

/**
 * Run the script's own rsync over `sourceDirectory` into a throwaway directory.
 *
 * Two deviations from the real command, both necessary and neither touching the
 * include/exclude rules under test: the destination is a temporary directory
 * rather than build/, so the real build output is left alone, and node_modules
 * is excluded because copying ~870MB per test would dominate the suite. The
 * excludes are appended after the script's own rules, so they cannot mask an
 * include the script relies on.
 */
function runRsyncFrom(sourceDirectory: string): string {
  const destination = createTemporaryDirectory('asr-custom-build-');

  const rsyncCommand = parseRsyncCommand()
    .replace(/\s+\.\/\s+build\/\s*$/, ' ')
    .concat(` --exclude=node_modules ./ "${destination}/"`);

  execFileSync('sh', ['-c', rsyncCommand], { cwd: sourceDirectory, stdio: 'ignore' });
  return destination;
}

/**
 * A tree holding one file per dot-directory the copy must drop, plus one file it
 * must keep as a control.
 *
 * The exclusions cannot be asserted against the working tree: a build host has
 * no .idea or .security-scan of its own, so a copy of the real tree would show
 * them absent whatever the rsync rules say. Planting them makes the assertion
 * mean the same thing on every machine. The .gitignore is the real one, because
 * it supplies the rules under test via --exclude-from.
 */
function createDotDirectoryFixture(): string {
  const fixturePath = createTemporaryDirectory('asr-custom-build-fixture-');

  fs.copyFileSync(path.join(REPO_ROOT, '.gitignore'), path.join(fixturePath, '.gitignore'));
  for (const relativePath of [...INTERNAL_DOT_DIRECTORY_FILES, CONTROL_FIXTURE_FILE]) {
    const absolutePath = path.join(fixturePath, relativePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, 'fixture\n');
  }

  return fixturePath;
}

/**
 * Every file .github holds in the working tree, as repository-relative paths.
 *
 * Read from the filesystem rather than from `git ls-files`, because in CI this
 * runs inside the copy custom-build produced, which has no git history to query.
 */
function listWorkingTreeGithubFiles(): string[] {
  const githubPath = path.join(REPO_ROOT, '.github');
  const files: string[] = [];

  if (!fs.existsSync(githubPath)) {
    throw new Error(`.github is missing from ${REPO_ROOT}; the copy under test cannot be checked against it`);
  }

  const walk = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(absolutePath);
      } else if (entry.isFile()) {
        files.push(path.relative(REPO_ROOT, absolutePath));
      }
    }
  };

  walk(githubPath);
  return files.sort();
}

/** Each copy is identical for every assertion against it, so both are built once. */
let deployedTreePath: string;
let fixtureCopyPath: string;

beforeAll(() => {
  deployedTreePath = runRsyncFrom(REPO_ROOT);
  fixtureCopyPath = runRsyncFrom(createDotDirectoryFixture());
});

afterAll(() => {
  for (const directory of temporaryDirectories) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('custom-build', () => {
  describe('the deployed copy', () => {
    it.each(REQUIRED_DEPLOYED_PATHS)('includes %s, which .gitignore negates but rsync would drop', (requiredPath) => {
      // GIVEN the working tree copied by the script's own rsync command
      // WHEN the path is looked up in the copy
      const isPresent = fs.existsSync(path.join(deployedTreePath, requiredPath));

      // THEN it survived the copy
      expect(isPresent).toBe(true);
    });

    it('copies every file .github holds, not just the one asserted by the allowlist', () => {
      // GIVEN the set of .github files in the working tree
      const workingTreeFiles = listWorkingTreeGithubFiles();

      // WHEN the same set is listed from the copy
      const copiedFiles = workingTreeFiles.filter((relativePath) =>
        fs.existsSync(path.join(deployedTreePath, relativePath)),
      );

      // THEN the copy is complete, so a new template cannot go missing silently
      expect(workingTreeFiles.length).toBeGreaterThan(0);
      expect(copiedFiles).toEqual(workingTreeFiles);
    });
  });

  describe('the deployed copy of a tree holding internal dot-directories', () => {
    it.each(INTERNAL_DOT_DIRECTORY_FILES)('still excludes %s', (internalPath) => {
      // GIVEN a fixture tree copied by the script's own rsync command
      // WHEN the internal path is looked up in the copy
      const isPresent = fs.existsSync(path.join(fixtureCopyPath, internalPath));

      // THEN restoring .github did not also republish internal state
      expect(isPresent).toBe(false);
    });

    it(`still includes ${CONTROL_FIXTURE_FILE}, so the exclusions above are not vacuous`, () => {
      // GIVEN the same fixture tree, in which this file was planted too
      // WHEN it is looked up in the copy
      const isPresent = fs.existsSync(path.join(fixtureCopyPath, CONTROL_FIXTURE_FILE));

      // THEN the copy did keep what it is meant to keep
      expect(isPresent).toBe(true);
    });
  });
});
