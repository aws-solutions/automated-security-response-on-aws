// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import type { Config } from 'jest';

const config: Config = {
  roots: [
    '<rootDir>/lib',
    '<rootDir>/playbooks/AFSBP/test',
    '<rootDir>/playbooks/CIS120/test',
    '<rootDir>/playbooks/CIS140/test',
    '<rootDir>/playbooks/NEWPLAYBOOK/test',
    '<rootDir>/playbooks/PCI321/test',
    '<rootDir>/playbooks/SC/test',
    '<rootDir>/playbooks/NIST80053/test',
    '<rootDir>/remediation_runbooks',
    '<rootDir>/solution_deploy',
    '<rootDir>/test',
  ],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
};

export default config;
