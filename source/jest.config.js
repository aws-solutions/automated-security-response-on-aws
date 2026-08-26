// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// @ts-check

// In a CodeBuild build, os.cpus() reports the host's core count rather than the
// container's allocation, so jest over-spawns memory-heavy CDK-synth workers
// and can run out of memory. Pin an explicit worker count in the build pipeline
// and cap per-worker memory.
const runningInBuildPipeline = Boolean(process.env.CODEBUILD_BUILD_ID);

/** @type {import('jest').Config} */
const config = {
  maxWorkers: runningInBuildPipeline ? 2 : '50%',
  workerIdleMemoryLimit: '2GB',
  roots: [
    '<rootDir>/lib',
    '<rootDir>/playbooks/AFSBP/test',
    '<rootDir>/playbooks/CIS120/test',
    '<rootDir>/playbooks/CIS140/test',
    '<rootDir>/playbooks/CIS300/test',
    '<rootDir>/playbooks/NEWPLAYBOOK/test',
    '<rootDir>/playbooks/PCI321/test',
    '<rootDir>/playbooks/SC/test',
    '<rootDir>/playbooks/NIST80053/test',
    '<rootDir>/remediation_runbooks',
    '<rootDir>/solution_deploy',
    '<rootDir>/blueprints',
    '<rootDir>/test',
  ],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
  snapshotSerializers: ['<rootDir>/test/snapshot-serializer.ts'],
};

module.exports = config;
