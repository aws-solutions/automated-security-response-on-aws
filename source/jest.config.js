// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
module.exports = {
  roots: [
  '<rootDir>/test',
  '<rootDir>/playbooks/CIS120/test',
  '<rootDir>/playbooks/AFSBP/test',
  '<rootDir>/playbooks/PCI321/test',
  '<rootDir>/remediation_runbooks'
],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  }
};
